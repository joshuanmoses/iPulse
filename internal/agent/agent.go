package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/logging"
	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/security"
	"github.com/ipulse/ipulse/internal/traffic"
	"github.com/ipulse/ipulse/internal/version"
)

// Monitor is a collector that contributes scheduled work. Every collector in iPulse is
// expressed this way, so the agent has exactly one execution mechanism and one place
// where timeouts, panic recovery and statistics are handled.
type Monitor interface {
	// Name identifies the monitor.
	Name() string
	// Tasks returns the scheduled work this monitor needs.
	Tasks() []Task
}

// Closer is implemented by monitors that hold resources.
type Closer interface {
	Close() error
}

// Options configures a new agent.
type Options struct {
	Config *config.Config
	// ConfigResult carries the load warnings and checksum, for the start-up record.
	ConfigWarnings []string
	ConfigChecksum string
	// Mode is "service" or "foreground", recorded in the start-up event.
	Mode string
	// ForceConsole enables the stderr log sink regardless of configuration.
	ForceConsole bool
	// Now allows tests to control time-dependent start-up behaviour.
	Now func() time.Time
}

// Agent is the running iPulse instance.
type Agent struct {
	cfg  *config.Config
	log  *logging.Logger
	db   *database.DB
	plat platform.Provider
	caps platform.Capabilities

	state *State
	sched *Scheduler

	monitors []Monitor
	closers  []Closer

	// connectivity and speed are kept for the API, which runs them on demand.
	connectivity *connectivityMonitor
	speed        *speedMonitor
	connections  *connectionMonitor
	anomaly      *anomalyMonitor

	// selfTraffic records the bytes iPulse transfers, so its own speed tests are
	// excluded from traffic anomaly detection.
	selfTraffic *traffic.SelfTraffic

	// api is started by Run when the dashboard is enabled. It is stored behind an
	// interface so internal/agent does not import internal/api at the type level more
	// than necessary.
	server Server

	mode      string
	startedAt time.Time

	mu       sync.Mutex
	shutdown bool

	onceMu   sync.Mutex
	onceSeen map[string]time.Time

	// dnsPartialGate is shared so partial-failure reporting has one cooldown even
	// though it is evaluated from two code paths.
	dnsPartialGate *gate

	// Analysis pipeline: collectors publish samples, one goroutine consumes them.
	samples        chan []sample
	consumers      []sampleConsumer
	samplesDropped atomic.Int64
	analysisDone   chan struct{}
	// analysisStarted guards the shutdown wait: an agent that is closed before Run (a
	// failed start-up, or a test that drives the pipeline directly) must not block
	// waiting for a goroutine that was never launched.
	analysisStarted atomic.Bool

	reload chan struct{}
}

// Server is the local API/dashboard server the agent supervises.
type Server interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Addr() string
}

// New builds an agent: it prepares directories, opens the database and the logger,
// resolves the platform provider and registers every monitor.
func New(opts Options) (*Agent, error) {
	if opts.Config == nil {
		return nil, errors.New("agent: configuration is required")
	}
	cfg := opts.Config
	if opts.Mode == "" {
		opts.Mode = "foreground"
	}

	// Directories first: everything else depends on them, and their permissions are
	// re-applied on every start rather than trusted to the installer.
	if err := security.EnsureDir(cfg.Service.DataDir, security.DirMode); err != nil {
		return nil, err
	}
	if err := security.EnsureDir(cfg.Service.LogDir, security.DirMode); err != nil {
		return nil, err
	}

	db, err := database.Open(database.Options{
		Path:        cfg.Database.Path,
		BusyTimeout: cfg.Database.BusyTimeout.D(),
		FileMode:    security.DataFileMode,
	})
	if err != nil {
		return nil, err
	}
	if err := db.EnableAutoVacuum(context.Background()); err != nil {
		_ = err // not fatal: only affects space reclamation
	}

	log, logWarnings, err := logging.New(logging.Options{
		Config:       cfg.Logging,
		LogDir:       cfg.Service.LogDir,
		DB:           db,
		ForceConsole: opts.ForceConsole,
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	plat := platform.New()
	caps := plat.Capabilities()

	a := &Agent{
		cfg:          cfg,
		log:          log,
		db:           db,
		plat:         plat,
		caps:         caps,
		state:        NewState(version.Version, version.Platform(), caps),
		sched:        NewScheduler(log),
		mode:         opts.Mode,
		startedAt:    time.Now(),
		reload:       make(chan struct{}, 1),
		samples:      make(chan []sample, sampleQueueDepth),
		analysisDone: make(chan struct{}),
		selfTraffic:  traffic.NewSelfTraffic(30 * time.Minute),
	}
	a.dnsPartialGate = a.newGate()

	// Report the environment before anything else, so a support log always begins with
	// the facts: version, platform, privileges and what is degraded.
	a.logStartup(opts, logWarnings)

	if err := a.registerMonitors(); err != nil {
		_ = log.Close()
		_ = db.Close()
		return nil, err
	}
	// Restore state that must survive a restart: an open outage, and the learned
	// baselines.
	if a.connectivity != nil {
		a.connectivity.Restore(context.Background())
	}
	if a.anomaly != nil {
		if err := a.anomaly.Restore(context.Background()); err != nil {
			a.log.Emit(events.New(events.DatabaseError).
				WithField("Operation", "load baselines").
				WithField("Error", err))
		}
	}
	return a, nil
}

func (a *Agent) logStartup(opts Options, logWarnings []string) {
	ev := events.New(events.AgentStarted).
		WithField("Version", version.Version).
		WithField("Commit", version.Commit).
		WithField("BuildDate", version.BuildDate).
		WithField("Platform", version.Platform()).
		WithField("PID", os.Getpid()).
		WithField("Elevated", a.caps.Elevated).
		WithField("ConfigPath", a.cfg.Path()).
		WithField("DataDir", a.cfg.Service.DataDir).
		WithField("LogDir", a.cfg.Service.LogDir).
		WithField("Mode", a.mode)
	a.log.Emit(ev)

	a.log.Emit(events.New(events.ConfigLoaded).
		WithField("Path", a.cfg.Path()).
		WithField("Source", "file").
		WithField("Checksum", opts.ConfigChecksum).
		WithField("Warnings", len(opts.ConfigWarnings)))
	for _, w := range opts.ConfigWarnings {
		a.log.Emit(events.New(events.ConfigLoaded).WithSeverity(events.Notice).
			WithField("Warning", w))
	}
	for _, w := range logWarnings {
		a.log.Emit(events.New(events.PrivilegeLimited).WithSeverity(events.Notice).
			WithField("Feature", "logging sink").WithField("Impact", w))
	}

	a.log.Emit(events.New(events.DatabaseOpened).
		WithField("Path", a.db.Path()).
		WithField("SchemaVersion", a.db.SchemaVersion()).
		WithField("Migrations", a.db.MigrationsApplied()).
		WithField("SizeBytes", a.db.SizeBytes()).
		WithField("Journal", "WAL"))

	// Privilege limitations are reported once at start-up rather than on every cycle.
	report := security.BuildPrivilegeReport(security.Capabilities{
		Platform:           a.caps.Platform,
		Elevated:           a.caps.Elevated,
		Interfaces:         a.caps.Interfaces,
		Routes:             a.caps.Routes,
		Connections:        a.caps.Connections,
		ProcessAttribution: a.caps.ProcessAttribution,
		Wireless:           a.caps.Wireless,
		ICMP:               a.caps.ICMP,
		Traceroute:         a.caps.Traceroute,
		DNSServers:         a.caps.DNSServers,
	})
	for _, f := range report.Degraded() {
		a.log.Emit(events.New(events.PrivilegeLimited).
			WithField("Feature", f.Feature).
			WithField("Required", f.Required).
			WithField("Platform", a.caps.Platform).
			WithField("Fallback", f.Fallback).
			WithField("Impact", f.Impact))
	}
	for _, w := range security.AuditPaths(a.cfg.Path(), a.cfg.Service.DataDir, a.cfg.Service.LogDir) {
		a.log.Emit(events.New(events.PrivilegeLimited).WithSeverity(events.Warning).
			WithField("Feature", "file permissions").
			WithField("Path", w.Path).
			WithField("Impact", w.Reason))
	}
}

// Run starts every task and blocks until the context is cancelled. ready is called once
// the agent is fully serving, which is what tells systemd or the SCM that start-up
// finished.
func (a *Agent) Run(ctx context.Context, ready func()) error {
	if a.server != nil {
		if err := a.server.Start(ctx); err != nil {
			// A busy port must not stop monitoring: log it and carry on without the
			// dashboard, because measurement is the primary function.
			a.log.Emit(events.New(events.APIStopped).WithSeverity(events.Error).
				WithField("Reason", err.Error()))
		} else {
			a.log.Emit(events.New(events.APIStarted).
				WithField("Address", a.cfg.Dashboard.Address).
				WithField("Port", a.cfg.Dashboard.Port).
				WithField("TLS", a.cfg.Dashboard.TLSCertFile != "").
				WithField("AuthRequired", a.cfg.Dashboard.AuthToken != "").
				WithField("Loopback", isLoopbackAddress(a.cfg.Dashboard.Address)))
		}
	}

	if len(a.consumers) > 0 {
		a.analysisStarted.Store(true)
		go a.runAnalysis(ctx)
	} else {
		close(a.analysisDone)
	}

	a.sched.Start(ctx)
	if ready != nil {
		ready()
	}

	// Watchdog support: when systemd asks for one, ping at half the configured interval.
	watchdog := a.startWatchdog(ctx)

	<-ctx.Done()
	if watchdog != nil {
		watchdog()
	}
	return a.Shutdown()
}

// Shutdown stops the agent, flushing logs and closing the database. It is safe to call
// more than once.
func (a *Agent) Shutdown() error {
	a.mu.Lock()
	if a.shutdown {
		a.mu.Unlock()
		return nil
	}
	a.shutdown = true
	a.mu.Unlock()

	timeout := a.cfg.Service.ShutdownTimeout.D()
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			a.log.Emit(events.New(events.APIStopped).WithField("Reason", err.Error()))
		} else {
			a.log.Emit(events.New(events.APIStopped).WithField("Reason", "shutdown"))
		}
	}

	// Wait for in-flight tasks, bounded by the shutdown timeout.
	done := make(chan struct{})
	go func() { a.sched.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	// Then let the analysis pipeline drain, so the last samples are still folded into
	// the baselines that are about to be persisted.
	if a.analysisStarted.Load() || len(a.consumers) == 0 {
		select {
		case <-a.analysisDone:
		case <-ctx.Done():
		}
	}

	for _, c := range a.closers {
		if err := c.Close(); err != nil {
			a.log.Emit(events.New(events.InternalError).
				WithField("Component", "shutdown").WithField("Error", err))
		}
	}

	stats := a.log.Stats()
	a.log.Emit(events.New(events.AgentStopped).
		WithField("Reason", "signal").
		WithField("Uptime", time.Since(a.startedAt)).
		WithField("EventsLogged", stats.Written).
		WithField("EventsDropped", stats.Dropped))

	var firstErr error
	if err := a.log.Close(); err != nil {
		firstErr = err
	}
	if err := a.db.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Reload re-reads the configuration file and applies what can be changed at runtime.
// Settings that cannot (bind address, database path) are reported as needing a restart.
func (a *Agent) Reload() {
	res, err := config.Load(a.cfg.Path())
	if err != nil {
		problems := err.Error()
		a.log.Emit(events.New(events.ConfigInvalid).
			WithField("Path", a.cfg.Path()).
			WithField("Errors", problems).
			WithField("UsingPrevious", true))
		return
	}
	newCfg := res.Config

	var restartNeeded []string
	if newCfg.Dashboard.Address != a.cfg.Dashboard.Address || newCfg.Dashboard.Port != a.cfg.Dashboard.Port {
		restartNeeded = append(restartNeeded, "dashboard.address/port")
	}
	if newCfg.Database.Path != a.cfg.Database.Path {
		restartNeeded = append(restartNeeded, "database.path")
	}
	if newCfg.Service.LogDir != a.cfg.Service.LogDir {
		restartNeeded = append(restartNeeded, "service.log_dir")
	}
	// Intervals are read from the configuration when the scheduler is built, so an
	// interval change also needs a restart; saying so is better than pretending.
	if newCfg.Monitoring != a.cfg.Monitoring {
		restartNeeded = append(restartNeeded, "monitoring intervals")
	}

	changed := 0
	if newCfg.Logging.Level != a.cfg.Logging.Level {
		if err := a.log.SetLevel(newCfg.Logging.Level); err == nil {
			changed++
		}
	}
	// Thresholds are read from the live configuration on every evaluation, so replacing
	// the pointed-to values applies immediately.
	a.cfg.Alerts = newCfg.Alerts
	a.cfg.Baseline = newCfg.Baseline
	a.cfg.Correlation = newCfg.Correlation
	a.cfg.Health = newCfg.Health
	a.cfg.Traffic = newCfg.Traffic
	a.cfg.Destinations = newCfg.Destinations
	a.cfg.Lateral = newCfg.Lateral
	a.cfg.ThreatIntel = newCfg.ThreatIntel
	a.cfg.SpeedTest.ExpectedDownloadMbps = newCfg.SpeedTest.ExpectedDownloadMbps
	a.cfg.SpeedTest.ExpectedUploadMbps = newCfg.SpeedTest.ExpectedUploadMbps
	a.cfg.Logging.Level = newCfg.Logging.Level
	changed++

	_ = a.db.RecordConfig(context.Background(), res.Path, res.Checksum, version.Version,
		strings.Join(res.Warnings, "; "), true)

	a.log.Emit(events.New(events.ConfigReloaded).
		WithField("Path", res.Path).
		WithField("Changed", changed).
		WithField("AppliedImmediately", true).
		WithField("RequiresRestart", strings.Join(restartNeeded, ",")))
}

// ReloadRequests exposes the channel the process signal handler writes to.
func (a *Agent) ReloadRequests() chan<- struct{} { return a.reload }

// State exposes the runtime state for the API and CLI.
func (a *Agent) State() *State { return a.state }

// Config exposes the live configuration.
func (a *Agent) Config() *config.Config { return a.cfg }

// DB exposes the database for the API.
func (a *Agent) DB() *database.DB { return a.db }

// Logger exposes the logger.
func (a *Agent) Logger() *logging.Logger { return a.log }

// Scheduler exposes the scheduler, so the API can trigger manual tests.
func (a *Agent) Scheduler() *Scheduler { return a.sched }

// Platform exposes the platform provider.
func (a *Agent) Platform() platform.Provider { return a.plat }

// Capabilities returns the platform capability report.
func (a *Agent) Capabilities() platform.Capabilities { return a.caps }

// SetServer attaches the API server. Called by the process entry point so the agent
// does not need to import the API package.
func (a *Agent) SetServer(s Server) { a.server = s }

// startWatchdog pings the systemd watchdog if one is configured, and returns a stop
// function.
func (a *Agent) startWatchdog(ctx context.Context) func() {
	if !watchdogEnabled() {
		return nil
	}
	interval := watchdogInterval() / 2
	if interval <= 0 {
		return nil
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				notifyWatchdog()
			}
		}
	}()
	return func() { close(stop) }
}

// recoverPanic converts a panic in a component into a reported event, so one broken
// detector cannot stop the agent.
func (a *Agent) recoverPanic(component string) {
	if r := recover(); r != nil {
		a.log.Emit(events.New(events.PanicRecovered).
			WithField("Component", component).
			WithField("Panic", fmt.Sprint(r)).
			WithField("Stack", string(debug.Stack())))
	}
}

func isLoopbackAddress(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || strings.HasPrefix(addr, "127.")
}
