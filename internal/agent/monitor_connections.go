package agent

import (
	"context"
	"errors"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/util"
)

// connectionMonitor samples the active TCP and UDP connection table.
//
// This is the input to destination analysis, threat matching and lateral-movement
// detection, so it runs continuously on a short interval. Only metadata is collected:
// endpoints, state, and the owning process where the platform permits it.
type connectionMonitor struct {
	a         *Agent
	collector *network.Collector
	// latest is the most recent snapshot, shared with the detectors that need it.
	latest network.Snapshot
	// consumers are notified of each snapshot in the collector's goroutine.
	consumers []connectionConsumer
}

// connectionConsumer receives each connection snapshot. Destination analysis, threat
// matching and lateral detection are all expressed this way, so the socket table is read
// once per cycle no matter how many detectors need it.
type connectionConsumer interface {
	Connections(ctx context.Context, snap network.Snapshot) error
	Name() string
}

func newConnectionMonitor(a *Agent) *connectionMonitor {
	internalRanges, invalid := util.ParsePrefixes(a.cfg.Lateral.ExtraPrivateRanges)
	for _, bad := range invalid {
		a.log.Emit(events.New(events.ConfigInvalid).WithSeverity(events.Warning).
			WithField("Path", a.cfg.Path()).
			WithField("Errors", "lateral.extra_private_ranges entry is not a CIDR prefix: "+bad).
			WithField("UsingPrevious", false))
	}
	ignoreDest, badDest := util.ParsePrefixes(a.cfg.Destinations.IgnoreDestinations)
	for _, bad := range badDest {
		// A hostname in ignore_destinations is legitimate but cannot be matched against
		// a socket table, which only has addresses; say so rather than silently ignoring.
		a.log.Emit(events.New(events.ConfigInvalid).WithSeverity(events.Notice).
			WithField("Path", a.cfg.Path()).
			WithField("Errors", "destinations.ignore_destinations entry is not an address or CIDR and cannot be matched against connections: "+bad).
			WithField("UsingPrevious", false))
	}

	return &connectionMonitor{
		a: a,
		collector: network.NewCollector(network.Config{
			IncludeUDP:         a.cfg.Connections.IncludeUDP,
			IncludeListening:   a.cfg.Connections.IncludeListening,
			IncludeLoopback:    a.cfg.Connections.IncludeLoopback,
			ResolveProcess:     a.cfg.Connections.ResolveProcess,
			Max:                a.cfg.Connections.MaxConnectionsPerSample,
			InternalRanges:     internalRanges,
			IgnoreProcesses:    a.cfg.Destinations.IgnoreProcesses,
			IgnoreDestinations: ignoreDest,
			Privacy: network.Privacy{
				CollectProcessNames:    a.cfg.Privacy.CollectProcessNames,
				CollectExecutablePaths: a.cfg.Privacy.CollectExecutablePaths,
				CollectUsernames:       a.cfg.Privacy.CollectUsernames,
				AnonymizeLocal:         a.cfg.Privacy.AnonymizeLocalAddresses,
			},
		}, a.plat),
	}
}

// AddConsumer registers a detector that needs each connection snapshot.
func (m *connectionMonitor) AddConsumer(c connectionConsumer) {
	m.consumers = append(m.consumers, c)
}

func (m *connectionMonitor) Name() string { return "connections" }

func (m *connectionMonitor) Tasks() []Task {
	return []Task{{
		Name:       "connections",
		Interval:   m.a.cfg.Monitoring.ConnectionInterval.D(),
		Timeout:    30 * time.Second,
		RunOnStart: true,
		Fn:         m.run,
	}}
}

// Latest returns the most recent snapshot.
func (m *connectionMonitor) Latest() network.Snapshot { return m.latest }

func (m *connectionMonitor) run(ctx context.Context) error {
	now := time.Now()
	snap, err := m.collector.Collect(now)
	if err != nil {
		if errors.Is(err, platform.ErrUnsupported) || errors.Is(err, platform.ErrPermission) {
			m.a.once("connections-unavailable", func() {
				m.a.log.Emit(events.New(events.PrivilegeLimited).
					WithField("Feature", "Active connection table").
					WithField("Platform", m.a.caps.Platform).
					WithField("Impact", "connection, destination and lateral analysis are unavailable").
					WithField("Error", err))
			})
			return nil
		}
		return err
	}
	m.latest = snap

	if err := m.a.db.UpsertConnections(ctx, snap.Connections); err != nil {
		return err
	}
	if err := m.a.db.InsertMeasurements(ctx, []database.Measurement{
		{Time: now, Metric: database.MetricConnCount, Value: float64(snap.Total), Unit: "count", OK: true},
		{Time: now, Metric: database.MetricDistinctDests,
			Value: float64(network.DistinctExternalDestinations(snap)), Unit: "count", OK: true},
	}); err != nil {
		return err
	}
	m.a.publishSamples(now,
		sample{Metric: database.MetricConnCount, Value: float64(snap.Total), Valid: true},
		sample{Metric: database.MetricDistinctDests,
			Value: float64(network.DistinctExternalDestinations(snap)), Valid: true},
	)

	m.a.state.Update(func(s *Snapshot) { s.ActiveConnections = snap.Total })

	// Report degraded attribution once: an operator reading connection events with no
	// process names should know why.
	if m.a.cfg.Connections.ResolveProcess && snap.Total > 0 && snap.WithProcess == 0 {
		m.a.once("connections-no-attribution", func() {
			m.a.log.Emit(events.New(events.PrivilegeLimited).
				WithField("Feature", "Process attribution for connections").
				WithField("Platform", m.a.caps.Platform).
				WithField("Impact", "connections are recorded without a process name").
				WithField("Detail", "no connection in this sample could be attributed"))
		})
	}

	for _, c := range m.consumers {
		if err := c.Connections(ctx, snap); err != nil {
			m.a.log.Emit(events.New(events.CollectorError).
				WithField("Collector", c.Name()).
				WithField("Error", err))
		}
	}
	return nil
}
