package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/routing"
)

// routeMonitor measures the path to a few stable destinations and reports significant
// changes.
//
// One destination is measured per cycle, round-robin, on a long interval. Path
// measurement is the most visible traffic iPulse generates - intermediate routers see it
// and some operators notice it - so it is deliberately infrequent and narrow.
type routeMonitor struct {
	a      *Agent
	tracer *routing.Tracer
	next   atomic.Uint64
}

func newRouteMonitor(a *Agent) *routeMonitor {
	return &routeMonitor{
		a: a,
		tracer: routing.New(routing.Config{
			MaxHops:      a.cfg.Routing.MaxHops,
			ProbesPerHop: a.cfg.Routing.ProbesPerHop,
			Timeout:      2 * time.Second,
			TotalTimeout: a.cfg.Routing.Timeout.D(),
		}),
	}
}

func (m *routeMonitor) Name() string { return "routing" }

func (m *routeMonitor) Tasks() []Task {
	return []Task{
		{
			Name:         "route",
			Interval:     m.a.cfg.Monitoring.RouteInterval.D(),
			Timeout:      m.a.cfg.Routing.Timeout.D() + 30*time.Second,
			Jitter:       time.Minute,
			InitialDelay: 2 * time.Minute,
			RunOnStart:   true,
			Fn:           m.run,
		},
		{
			// On-demand path measurement for the CLI and the dashboard.
			Name:       "traceroute",
			ManualOnly: true,
			Timeout:    m.a.cfg.Routing.Timeout.D() + 30*time.Second,
			Fn:         m.run,
		},
	}
}

func (m *routeMonitor) run(ctx context.Context) error {
	dests := m.a.cfg.Routing.Destinations
	if len(dests) == 0 {
		return nil
	}
	if !m.a.state.Online() {
		return nil
	}
	if ok, err := m.tracer.Available(); !ok {
		// Report the limitation once rather than failing every cycle.
		m.a.once("traceroute-unavailable", func() {
			m.a.log.Emit(events.New(events.TracerouteUnavail).
				WithField("Reason", err).
				WithField("Platform", m.a.caps.Platform).
				WithField("Remedy", tracerouteRemedy()))
		})
		return nil
	}

	dest := dests[int(m.next.Add(1)-1)%len(dests)]
	path, err := m.tracer.Trace(ctx, dest)
	if err != nil {
		return err
	}
	now := time.Now()

	// Compare with the previous measurement for this destination.
	previous, hadPrevious, err := m.a.db.LatestRoutePath(ctx, dest)
	if err != nil {
		return err
	}
	changed := false
	var diff routing.Diff
	if hadPrevious {
		var prevPath routing.Path
		if json.Unmarshal([]byte(previous.Path), &prevPath) == nil {
			diff = routing.Compare(prevPath, path, m.a.cfg.Routing.HopChangeTolerance)
			changed = diff.Changed
		}
	}

	encoded, err := json.Marshal(path)
	if err != nil {
		return err
	}
	if _, err := m.a.db.InsertRoutePath(ctx, database.RoutePath{
		Time: now, Destination: dest, HopCount: path.HopCount(), Path: string(encoded),
		Changed: changed, RTTMS: msOf(path.RTT), Method: path.Method,
	}); err != nil {
		return err
	}
	if err := m.a.db.InsertMeasurement(ctx, database.Measurement{
		Time: now, Metric: database.MetricHopCount, Value: float64(path.HopCount()),
		Unit: "hops", Target: dest, OK: path.Complete,
	}); err != nil {
		return err
	}

	m.a.log.Emit(events.New(events.TracerouteCompleted).
		WithField("Destination", dest).
		WithField("Hops", path.HopCount()).
		WithFields(events.Fields{}.AddDuration("Duration", path.Duration)).
		WithField("Path", path.Signature()).
		WithField("Method", path.Method).
		WithField("Complete", path.Complete))

	if changed {
		var prevPath routing.Path
		_ = json.Unmarshal([]byte(previous.Path), &prevPath)
		m.a.log.Emit(events.New(events.RouteChanged).
			WithField("Destination", dest).
			WithField("PreviousHops", previous.HopCount).
			WithField("CurrentHops", path.HopCount()).
			WithField("ChangedAt", previous.Time).
			WithField("PreviousPath", prevPath.Signature()).
			WithField("CurrentPath", path.Signature()).
			WithField("ChangedHops", diff.ChangedHops).
			WithField("FirstChangedHop", diff.FirstChange).
			WithField("VPNActive", m.a.state.VPNActive()))
	}
	if hadPrevious && previous.HopCount != path.HopCount() && path.Complete {
		m.a.log.Emit(events.New(events.HopCountChanged).
			WithField("Destination", dest).
			WithField("PreviousHopCount", previous.HopCount).
			WithField("CurrentHopCount", path.HopCount()).
			WithField("Delta", path.HopCount()-previous.HopCount))
	}
	return nil
}

// tracerouteRemedy names the specific change that would enable path measurement.
func tracerouteRemedy() string {
	if strings.HasPrefix(runtimeGOOS(), "windows") {
		return "run the iPulse service as Administrator"
	}
	return "grant CAP_NET_RAW to the iPulse service, or widen net.ipv4.ping_group_range " +
		"to include the service's group"
}
