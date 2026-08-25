package agent

import (
	"context"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// registerMonitors builds the collector set and registers each monitor's tasks with the
// scheduler. Every collector in iPulse appears here, which makes the agent's whole
// workload readable in one place.
func (a *Agent) registerMonitors() error {
	a.monitors = a.buildMonitors()

	for _, m := range a.monitors {
		for _, t := range m.Tasks() {
			if err := a.sched.Add(t); err != nil {
				return err
			}
		}
		if c, ok := m.(Closer); ok {
			a.closers = append(a.closers, c)
		}
	}
	for _, t := range a.maintenanceTasks() {
		if err := a.sched.Add(t); err != nil {
			return err
		}
	}
	return nil
}

// maintenanceTasks are the agent's own housekeeping jobs: retention pruning and the
// periodic availability summary.
func (a *Agent) maintenanceTasks() []Task {
	return []Task{
		{
			Name:         "retention",
			Interval:     a.cfg.Monitoring.RetentionInterval.D(),
			Timeout:      10 * time.Minute,
			InitialDelay: 2 * time.Minute,
			Fn:           a.pruneDatabase,
		},
		{
			Name:         "availability-report",
			Interval:     a.cfg.Monitoring.AvailabilityInterval.D(),
			Timeout:      time.Minute,
			InitialDelay: 5 * time.Minute,
			Fn:           a.reportAvailability,
		},
		{
			Name:       "state-refresh",
			Interval:   30 * time.Second,
			Timeout:    20 * time.Second,
			RunOnStart: true,
			Fn:         a.refreshCounters,
		},
	}
}

func (a *Agent) pruneDatabase(ctx context.Context) error {
	res, err := a.db.Prune(ctx, a.cfg.Database)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-a.cfg.Baseline.MaxSampleAge.D())
	if n, err := a.db.PruneBaselines(ctx, cutoff); err == nil && n > 0 {
		res.RowsDeleted += n
		res.ByTable["baselines"] = n
	}
	if a.cfg.ThreatIntel.Enabled {
		if n, err := a.db.ExpireIndicators(ctx, time.Now().Add(-a.cfg.ThreatIntel.ExpireAfter.D())); err == nil && n > 0 {
			res.RowsDeleted += n
			res.ByTable["threat_indicators"] = n
		}
	}

	ev := events.New(events.RetentionCompleted).
		WithField("RowsDeleted", res.RowsDeleted).
		WithField("RowsRolledUp", res.RowsRolledUp).
		WithField("Tables", joinStrings(res.Tables(), ",")).
		WithFields(events.Fields{}.AddDuration("Duration", res.Duration)).
		WithFields(events.Fields{}.
			AddBytes("SizeBefore", float64(res.SizeBefore)).
			AddBytes("SizeAfter", float64(res.SizeAfter)).
			AddBytes("Reclaimed", float64(res.SizeBefore-res.SizeAfter)))
	a.log.Emit(ev)

	// A database over its ceiling is worth flagging: retention is configured too
	// loosely for this host's activity.
	if a.cfg.Database.MaxSizeMB > 0 && res.SizeAfter > int64(a.cfg.Database.MaxSizeMB)<<20 {
		a.log.Emit(events.New(events.DatabaseError).WithSeverity(events.Warning).
			WithField("Operation", "retention").
			WithFields(events.Fields{}.AddBytes("Size", float64(res.SizeAfter))).
			WithField("Limit", a.cfg.Database.MaxSizeMB).
			WithField("Error", "database exceeds database.max_size_mb; shorten retention"))
	}
	return nil
}

func (a *Agent) reportAvailability(ctx context.Context) error {
	window := a.cfg.Monitoring.AvailabilityInterval.D()
	av, err := a.db.AvailabilitySince(ctx, time.Now().Add(-window))
	if err != nil {
		return err
	}
	a.log.Emit(events.New(events.AvailabilityReport).
		WithField("Window", window).
		WithFields(events.Fields{}.AddUnitPrec("AvailabilityPercent", av.Percent, "%", 3)).
		WithField("Outages", av.Outages).
		WithField("TotalDowntime", av.Downtime).
		WithField("LongestOutage", av.LongestOutage).
		WithField("MTBF", av.MTBF))

	_ = a.db.InsertMeasurement(ctx, database.Measurement{
		Time: time.Now(), Metric: database.MetricAvailabilityPct,
		Value: av.Percent, Unit: "%", OK: true,
	})
	a.state.Update(func(s *Snapshot) { s.AvailabilityPct = av.Percent })
	return nil
}

// refreshCounters keeps the cheap summary counters in the snapshot current, so the
// status view and dashboard never have to run aggregate queries themselves.
func (a *Agent) refreshCounters(ctx context.Context) error {
	now := time.Now()

	if av, err := a.db.AvailabilitySince(ctx, now.Add(-24*time.Hour)); err == nil {
		a.state.Update(func(s *Snapshot) {
			s.AvailabilityPct = av.Percent
			s.Outages24h = av.Outages
		})
	}
	if outage, open, err := a.db.CurrentOutage(ctx); err == nil {
		a.state.Update(func(s *Snapshot) {
			if open {
				o := outage
				s.CurrentOutage = &o
			} else {
				s.CurrentOutage = nil
			}
		})
	}
	if n, err := a.db.DestinationCount(ctx); err == nil {
		a.state.Update(func(s *Snapshot) { s.KnownDestinations = n })
	}
	if total, _, err := a.db.IndicatorCount(ctx); err == nil {
		a.state.Update(func(s *Snapshot) { s.Indicators = total })
	}
	if matches, err := a.db.QueryThreatMatches(ctx, now.Add(-24*time.Hour), 1000); err == nil {
		a.state.Update(func(s *Snapshot) { s.ThreatMatches24h = int64(len(matches)) })
	}
	stats := a.log.Stats()
	a.state.Update(func(s *Snapshot) {
		s.EventsLogged = stats.Written
		s.ExpectedDownloadMbps = a.cfg.SpeedTest.ExpectedDownloadMbps
		s.ExpectedUploadMbps = a.cfg.SpeedTest.ExpectedUploadMbps
	})
	return nil
}

func joinStrings(in []string, sep string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
