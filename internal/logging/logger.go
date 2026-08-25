package logging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// Log file names inside the log directory.
const (
	TextLogName  = "ipulse.log"
	JSONLogName  = "ipulse.jsonl"
	AuditLogName = "ipulse-audit.log"
)

// queueDepth bounds the in-flight event queue. Logging is asynchronous so a slow disk
// can never block a probe; if the queue fills, events are dropped and counted rather
// than stalling the agent, and the drop count is reported.
const queueDepth = 4096

type item struct {
	ev    events.Event
	flush chan struct{}
}

// Logger is the iPulse logging engine: one goroutine fans each event out to every
// configured sink and to in-process subscribers.
type Logger struct {
	minSev events.Severity
	sinks  []Sink

	queue chan item
	stop  chan struct{}
	wg    sync.WaitGroup

	written   atomic.Int64
	dropped   atomic.Int64
	sinkFails sync.Map // sink name -> *atomic.Int64

	subMu sync.RWMutex
	subs  []chan events.Event

	closeOnce sync.Once
}

// Options configures the logger.
type Options struct {
	Config config.LoggingConfig
	LogDir string
	// DB enables the searchable events table. Optional.
	DB *database.DB
	// ForceConsole turns on the stderr sink regardless of configuration, for
	// foreground runs and for `ipulse run --verbose`.
	ForceConsole bool
}

// New builds a logger. Sinks that cannot be created are reported as warnings rather
// than failures: losing journald must not stop the agent from logging to disk.
func New(opts Options) (*Logger, []string, error) {
	cfg := opts.Config
	minSev, err := events.ParseSeverity(cfg.Level)
	if err != nil {
		return nil, nil, fmt.Errorf("logging: %w", err)
	}
	osSev, err := events.ParseSeverity(cfg.SyslogSeverity)
	if err != nil {
		osSev = events.Notice
	}
	mode := parseFileMode(cfg.FileMode)

	l := &Logger{
		minSev: minSev,
		queue:  make(chan item, queueDepth),
		stop:   make(chan struct{}),
	}
	var warnings []string

	rc := func(name string) rotateConfig {
		return rotateConfig{
			Path:          filepath.Join(opts.LogDir, name),
			MaxBytes:      int64(cfg.MaxFileMB) << 20,
			MaxArchives:   cfg.MaxArchives,
			RetentionDays: cfg.RetentionDays,
			Compress:      cfg.Compress,
			RotateDaily:   cfg.RotateDaily,
			Mode:          mode,
		}
	}

	if cfg.Text {
		s, err := newTextSink(rc(TextLogName))
		if err != nil {
			// Losing the primary log file is serious enough to fail start-up: the
			// operator asked for it and a silent downgrade would be worse.
			return nil, warnings, err
		}
		l.sinks = append(l.sinks, s)
	}
	if cfg.JSON {
		s, err := newJSONLSink(rc(JSONLogName))
		if err != nil {
			return nil, warnings, err
		}
		l.sinks = append(l.sinks, s)
	}
	if cfg.Database && opts.DB != nil {
		l.sinks = append(l.sinks, newDBSink(opts.DB))
	}
	if cfg.Syslog {
		if s, err := newSyslogSink(osSev); err != nil {
			// Both OS log sinks are enabled by default so one configuration file works
			// on both platforms; the inapplicable one is silently skipped.
			if !errors.Is(err, ErrSinkUnsupported) {
				warnings = append(warnings, "logging: "+err.Error())
			}
		} else {
			l.sinks = append(l.sinks, s)
		}
	}
	if cfg.EventLog {
		if s, err := newEventLogSink(osSev); err != nil {
			if !errors.Is(err, ErrSinkUnsupported) {
				warnings = append(warnings, "logging: "+err.Error())
			}
		} else {
			l.sinks = append(l.sinks, s)
		}
	}
	if cfg.Console || opts.ForceConsole {
		l.sinks = append(l.sinks, newConsoleSink())
	}
	if len(l.sinks) == 0 {
		warnings = append(warnings, "logging: no sink is active; events will only be visible to in-process consumers")
	}

	l.wg.Add(1)
	go l.run()
	return l, warnings, nil
}

func parseFileMode(s string) os.FileMode {
	var mode os.FileMode = 0o640
	if s == "" {
		return mode
	}
	var parsed uint32
	if _, err := fmt.Sscanf(s, "%o", &parsed); err == nil && parsed != 0 {
		return os.FileMode(parsed)
	}
	return mode
}

// Emit queues an event. It never blocks: if the queue is full the event is dropped and
// counted, because stalling a probe to write a log line would corrupt the measurement
// the log line is about.
func (l *Logger) Emit(ev events.Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Name == "" {
		ev.Name = events.Name(ev.Code)
	}
	if ev.Category == "" {
		ev.Category = events.CategoryForCode(ev.Code)
	}
	select {
	case l.queue <- item{ev: ev}:
	default:
		l.dropped.Add(1)
	}
}

// Event is a convenience wrapper: build an event from the catalog and emit it.
func (l *Logger) Event(code int, fields ...events.Field) {
	l.Emit(events.New(code, fields...))
}

// Errorf emits an internal error event with a formatted Error field. Used by
// components that need to report a failure with no more specific event.
func (l *Logger) Errorf(code int, component string, format string, args ...any) {
	l.Emit(events.New(code).
		WithField("Component", component).
		WithField("Error", fmt.Sprintf(format, args...)))
}

// Subscribe returns a channel that receives every emitted event, with the database id
// populated when the database sink is active. Subscribers must keep draining: a full
// subscriber channel drops events for that subscriber only.
func (l *Logger) Subscribe(buffer int) <-chan events.Event {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan events.Event, buffer)
	l.subMu.Lock()
	l.subs = append(l.subs, ch)
	l.subMu.Unlock()
	return ch
}

func (l *Logger) run() {
	defer l.wg.Done()
	for {
		select {
		case it, ok := <-l.queue:
			if !ok {
				return
			}
			if it.flush != nil {
				close(it.flush)
				continue
			}
			l.process(it.ev)
		case <-l.stop:
			// Drain whatever is queued so shutdown does not lose the final events.
			for {
				select {
				case it := <-l.queue:
					if it.flush != nil {
						close(it.flush)
						continue
					}
					l.process(it.ev)
				default:
					return
				}
			}
		}
	}
}

func (l *Logger) process(ev events.Event) {
	// Sinks honour the configured level; subscribers always see everything, so a
	// quiet log level cannot silently disable the correlation engine.
	if ev.Severity >= l.minSev {
		for _, s := range l.sinks {
			// Suppressed events are kept out of the human-facing sinks but still
			// recorded in the database for forensics.
			if ev.Suppressed && s.Name() != "database" {
				continue
			}
			if a, ok := s.(idAssigner); ok {
				if id, err := a.WriteWithID(ev); err != nil {
					l.noteSinkError(s.Name(), err)
				} else if ev.ID == 0 {
					ev.ID = id
				}
				continue
			}
			if err := s.Write(ev); err != nil {
				l.noteSinkError(s.Name(), err)
			}
		}
		l.written.Add(1)
		l.reportRotations()
	}
	l.publish(ev)
}

func (l *Logger) publish(ev events.Event) {
	l.subMu.RLock()
	defer l.subMu.RUnlock()
	for _, ch := range l.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// noteSinkError reports a sink failure at most once per sink per 100 failures, so a
// persistently broken sink cannot fill the remaining sinks with error records.
func (l *Logger) noteSinkError(sink string, err error) {
	v, _ := l.sinkFails.LoadOrStore(sink, new(atomic.Int64))
	counter := v.(*atomic.Int64)
	n := counter.Add(1)
	if n != 1 && n%100 != 0 {
		return
	}
	ev := events.New(events.LogSinkError).
		WithField("Sink", sink).
		WithField("Error", err).
		WithField("Dropped", n)
	for _, s := range l.sinks {
		if s.Name() == sink {
			continue
		}
		_ = s.Write(ev)
	}
}

func (l *Logger) reportRotations() {
	for _, s := range l.sinks {
		r, ok := s.(rotationReporter)
		if !ok {
			continue
		}
		for _, info := range r.takeRotations() {
			ev := events.New(events.LogRotated).
				WithField("File", info.File).
				WithField("Archive", info.Archive).
				WithField("SizeBytes", info.SizeBytes).
				WithField("Compressed", info.Compressed).
				WithField("ArchivesRetained", info.ArchivesRetained).
				WithField("ArchivesDeleted", info.ArchivesDeleted)
			for _, sink := range l.sinks {
				_ = sink.Write(ev)
			}
		}
	}
}

// Flush blocks until every event queued so far has been written.
func (l *Logger) Flush() {
	done := make(chan struct{})
	select {
	case l.queue <- item{flush: done}:
	case <-time.After(2 * time.Second):
		return
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// Stats reports logger counters for the status view.
type Stats struct {
	Written int64    `json:"written"`
	Dropped int64    `json:"dropped"`
	Sinks   []string `json:"sinks"`
	Level   string   `json:"level"`
}

// Stats returns the current counters.
func (l *Logger) Stats() Stats {
	names := make([]string, 0, len(l.sinks))
	for _, s := range l.sinks {
		names = append(names, s.Name())
	}
	return Stats{
		Written: l.written.Load(),
		Dropped: l.dropped.Load(),
		Sinks:   names,
		Level:   l.minSev.String(),
	}
}

// SetLevel changes the minimum severity written to sinks, for configuration reload.
func (l *Logger) SetLevel(level string) error {
	sev, err := events.ParseSeverity(level)
	if err != nil {
		return err
	}
	l.minSev = sev
	return nil
}

// Level returns the active minimum severity.
func (l *Logger) Level() events.Severity { return l.minSev }

// Close flushes and closes every sink.
func (l *Logger) Close() error {
	var firstErr error
	l.closeOnce.Do(func() {
		l.Flush()
		close(l.stop)
		l.wg.Wait()
		for _, s := range l.sinks {
			if err := s.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		l.subMu.Lock()
		for _, ch := range l.subs {
			close(ch)
		}
		l.subs = nil
		l.subMu.Unlock()
	})
	return firstErr
}

// Discard returns a logger that drops everything, for tests and for CLI paths that
// must not write to the agent's log files.
func Discard() *Logger {
	l := &Logger{
		minSev: events.Critical + 1,
		queue:  make(chan item, 16),
		stop:   make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l
}

// SinkNames lists the active sinks, used by the status command.
func (l *Logger) SinkNames() string {
	names := make([]string, 0, len(l.sinks))
	for _, s := range l.sinks {
		names = append(names, s.Name())
	}
	return strings.Join(names, ",")
}
