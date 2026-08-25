package agent

import (
	"context"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/traffic"
)

// trafficMonitor samples interface counters and turns them into throughput.
//
// Detection of spikes and unusual volumes lives in the anomaly detectors, which consume
// the samples this monitor publishes. This monitor's job is to produce correct rates:
// counter resets handled, iPulse's own transfers excluded, and virtual interfaces left
// out so nothing is counted twice.
type trafficMonitor struct {
	a       *Agent
	sampler *traffic.Sampler
	errors  *gate
	// windows accumulates transferred volume per interface. Rates answer "how fast now";
	// volume answers "how much in the last few minutes", which is the question that
	// matters for an unexpected upload.
	windows map[string]*traffic.WindowAccumulator
	// volumeWindow is the accumulation period, also used as the metric's dimension so a
	// configuration change cannot be compared against a baseline built at another size.
	volumeWindow time.Duration
}

func newTrafficMonitor(a *Agent) *trafficMonitor {
	return &trafficMonitor{
		a: a,
		sampler: traffic.NewSampler(traffic.Config{
			Include:     a.cfg.Traffic.Interfaces,
			Exclude:     a.cfg.Traffic.ExcludeInterfaces,
			ExcludeSelf: a.cfg.Traffic.ExcludeSelfTraffic,
		}, a.selfTraffic),
		errors:       a.newGate(),
		windows:      map[string]*traffic.WindowAccumulator{},
		volumeWindow: 5 * time.Minute,
	}
}

func (m *trafficMonitor) Name() string { return "traffic" }

func (m *trafficMonitor) Tasks() []Task {
	return []Task{{
		Name:       "traffic",
		Interval:   m.a.cfg.Monitoring.TrafficInterval.D(),
		Timeout:    10 * time.Second,
		RunOnStart: true,
		Fn:         m.run,
	}}
}

func (m *trafficMonitor) run(ctx context.Context) error {
	ifaces, err := m.a.plat.Interfaces()
	if err != nil {
		return err
	}
	now := time.Now()
	samples := m.sampler.Sample(ifaces, now)
	if len(samples) == 0 {
		return nil
	}

	// Housekeeping: the self-traffic history only needs to cover the sampling window.
	m.a.selfTraffic.Prune(now.Add(-30 * time.Minute))

	active := m.a.state.CurrentInterface()
	var busSamples []sample

	for _, s := range samples {
		if err := m.a.db.InsertInterfaceSample(ctx, database.InterfaceSample{
			Time: s.Time, Interface: s.Interface,
			RxBytes: int64(s.RxBytes), TxBytes: int64(s.TxBytes),
			RxPackets: int64(s.RxPackets), TxPackets: int64(s.TxPackets),
			RxErrors: int64(s.RxErrors), TxErrors: int64(s.TxErrors),
			RxDropped: int64(s.RxDropped), TxDropped: int64(s.TxDropped),
			RxBps: s.RxBps, TxBps: s.TxBps,
			SelfRxBps: s.SelfRxBps, SelfTxBps: s.SelfTxBps,
		}); err != nil {
			return err
		}
		if !s.Usable() {
			// A counter reset produces no meaningful rate; recording the raw counters is
			// still useful, but nothing downstream should see a rate for it.
			continue
		}

		if err := m.a.db.InsertMeasurements(ctx, []database.Measurement{
			{Time: s.Time, Metric: database.MetricRxBps, Value: s.RxBps, Unit: "bps", Target: s.Interface, OK: true},
			{Time: s.Time, Metric: database.MetricTxBps, Value: s.TxBps, Unit: "bps", Target: s.Interface, OK: true},
		}); err != nil {
			return err
		}

		// Samples during iPulse's own transfers are not published for anomaly
		// detection: subtraction is proportional and therefore approximate, and a
		// speed test must never be able to produce a traffic anomaly.
		if !s.SelfActive {
			busSamples = append(busSamples,
				sample{Time: s.Time, Metric: database.MetricRxBps, Value: s.RxBps, Target: s.Interface, Valid: true},
				sample{Time: s.Time, Metric: database.MetricTxBps, Value: s.TxBps, Target: s.Interface, Valid: true},
			)
			busSamples = append(busSamples, m.accumulateVolume(s)...)
		}

		if s.Interface == active || (active == "" && s.TotalBps() > 0) {
			rx, tx := s.RxBps, s.TxBps
			m.a.state.Update(func(snap *Snapshot) {
				snap.RxBps = rx
				snap.TxBps = tx
			})
		}

		m.reportErrors(s, now)
	}

	m.a.publishSamples(now, busSamples...)
	return nil
}

// accumulateVolume folds the interval's bytes into the rolling window and publishes the
// window totals once a full window is available.
func (m *trafficMonitor) accumulateVolume(s traffic.Sample) []sample {
	acc, ok := m.windows[s.Interface]
	if !ok {
		acc = traffic.NewWindowAccumulator(m.volumeWindow)
		m.windows[s.Interface] = acc
	}
	// Subtract iPulse's own bytes from the volume as well as from the rate.
	selfRx := int64(s.SelfRxBps * s.Interval.Seconds() / 8)
	selfTx := int64(s.SelfTxBps * s.Interval.Seconds() / 8)
	acc.Add(s.Time, maxZero(s.RxDelta-selfRx), maxZero(s.TxDelta-selfTx))

	if !acc.Complete(s.Time) {
		// A partial window compared against a full-window baseline would look like a
		// drop in volume, so nothing is published until the window has filled.
		return nil
	}
	rx, tx, _ := acc.Totals(s.Time)
	return []sample{
		{Time: s.Time, Metric: database.MetricRxBytesWindow, Value: float64(rx), Target: s.Interface, Valid: true},
		{Time: s.Time, Metric: database.MetricTxBytesWindow, Value: float64(tx), Target: s.Interface, Valid: true},
	}
}

// VolumeWindow returns the accumulation period, for event fields.
func (m *trafficMonitor) VolumeWindow() time.Duration { return m.volumeWindow }

func maxZero(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// reportErrors raises the interface error-rate event. Physical problems show up here
// long before they show up as an outage.
func (m *trafficMonitor) reportErrors(s traffic.Sample, now time.Time) {
	threshold := m.a.cfg.Traffic.ErrorRateThreshold
	if threshold <= 0 || s.Interval <= 0 {
		return
	}
	rate := float64(s.ErrorsDelta+s.DroppedDelta) / s.Interval.Seconds()
	d := m.errors.Observe("iface-errors:"+s.Interface, rate >= threshold, now)
	if !d.Fire {
		return
	}
	m.a.log.Emit(events.New(events.InterfaceErrorsRising).
		WithField("Interface", s.Interface).
		WithField("RxErrors", s.RxErrors).
		WithField("TxErrors", s.TxErrors).
		WithField("RxDropped", s.RxDropped).
		WithField("TxDropped", s.TxDropped).
		WithField("Window", s.Interval).
		WithFields(events.Fields{}.AddUnitPrec("ErrorRate", rate, "/s", 2)))
}
