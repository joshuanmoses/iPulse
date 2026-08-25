package agent

import (
	"context"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/latency"
)

// latencyMonitor measures round-trip time, jitter and packet loss to the configured
// targets, and to the default gateway.
//
// Measuring the gateway alongside the Internet targets is what lets iPulse separate
// "the local network is slow" from "the Internet is slow": if gateway RTT rises with
// Internet RTT, the problem is local (saturation or Wi-Fi), and if only Internet RTT
// rises, it is upstream.
type latencyMonitor struct {
	a      *Agent
	prober *latency.Prober
	loss   *gate
}

func newLatencyMonitor(a *Agent) *latencyMonitor {
	cfg := a.cfg.Latency
	return &latencyMonitor{
		a: a,
		prober: latency.New(latency.Config{
			Method:  latency.Method(cfg.Method),
			Probes:  cfg.Probes,
			Spacing: cfg.Spacing.D(),
			Timeout: cfg.Timeout.D(),
			TCPPort: cfg.TCPPort,
		}),
		loss: a.newGate(),
	}
}

func (m *latencyMonitor) Name() string { return "latency" }

func (m *latencyMonitor) Tasks() []Task {
	// The cycle can take probes x (spacing + timeout) per target, so the timeout is
	// derived from the configuration rather than guessed.
	cfg := m.a.cfg.Latency
	perTarget := time.Duration(cfg.Probes) * (cfg.Spacing.D() + cfg.Timeout.D())
	timeout := perTarget*time.Duration(len(cfg.Targets)+1) + 5*time.Second

	return []Task{{
		Name:       "latency",
		Interval:   m.a.cfg.Monitoring.LatencyInterval.D(),
		Timeout:    timeout,
		Jitter:     m.a.cfg.Monitoring.Jitter.D(),
		RunOnStart: true,
		Fn:         m.run,
	}}
}

// Prober exposes the prober so other collectors (connectivity diagnostics, routing) can
// reuse the same ICMP capability detection and fallback behaviour.
func (m *latencyMonitor) Prober() *latency.Prober { return m.prober }

func (m *latencyMonitor) run(ctx context.Context) error {
	cfg := m.a.cfg.Latency
	now := time.Now()

	// Report the fallback once: an operator who sees TCP-derived loss figures should
	// know why they are coarser than usual.
	if m.prober.Method() == latency.MethodTCP && cfg.Method == "auto" {
		m.a.once("latency-tcp-fallback", func() {
			m.a.log.Emit(events.New(events.PrivilegeLimited).
				WithField("Feature", "ICMP latency and packet loss").
				WithField("Required", "CAP_NET_RAW or an unprivileged ping socket").
				WithField("Platform", m.a.caps.Platform).
				WithField("Fallback", "TCP connect timing").
				WithField("Impact", "packet loss is inferred from failed handshakes").
				WithField("Error", m.prober.ICMPError()))
		})
	}

	results := m.prober.ProbeAll(ctx, cfg.Targets)
	agg := latency.Aggregate_(results)

	var measurements []database.Measurement
	for _, r := range results {
		if !r.OK() {
			measurements = append(measurements, database.Measurement{
				Time: now, Metric: database.MetricPacketLossPct, Value: 100,
				Unit: "%", Target: r.Target, OK: false, Meta: r.Error,
			})
			continue
		}
		measurements = append(measurements,
			database.Measurement{Time: now, Metric: database.MetricLatencyMS, Value: r.AvgMS(),
				Unit: "ms", Target: r.Target, OK: true},
			database.Measurement{Time: now, Metric: database.MetricJitterMS, Value: r.JitterMS(),
				Unit: "ms", Target: r.Target, OK: true},
			database.Measurement{Time: now, Metric: database.MetricPacketLossPct, Value: r.LossPct,
				Unit: "%", Target: r.Target, OK: true},
		)
	}

	// The connection-level values (empty target) are what the health score, the
	// baselines and the dashboard read.
	if agg.Responded > 0 {
		measurements = append(measurements,
			database.Measurement{Time: now, Metric: database.MetricLatencyMS,
				Value: msOf(agg.Avg), Unit: "ms", OK: true},
			database.Measurement{Time: now, Metric: database.MetricJitterMS,
				Value: msOf(agg.Jitter), Unit: "ms", OK: true},
			database.Measurement{Time: now, Metric: database.MetricPacketLossPct,
				Value: agg.LossPct, Unit: "%", OK: true},
		)
	}

	// Gateway latency, which localises any degradation.
	if cfg.IncludeGateway {
		if gw := m.a.state.Gateway(); gw != "" {
			gwRes := m.prober.Probe(ctx, gw)
			if gwRes.OK() {
				measurements = append(measurements, database.Measurement{
					Time: now, Metric: database.MetricGatewayRTTMS, Value: gwRes.AvgMS(),
					Unit: "ms", Target: gw, OK: true,
				})
				m.a.state.Update(func(s *Snapshot) { s.GatewayRTTMS = gwRes.AvgMS() })
			}
		}
	}

	if err := m.a.db.InsertMeasurements(ctx, measurements); err != nil {
		return err
	}

	if agg.Responded > 0 {
		m.a.state.Update(func(s *Snapshot) {
			s.LatencyMS = msOf(agg.Avg)
			s.JitterMS = msOf(agg.Jitter)
			s.PacketLossPct = agg.LossPct
		})
	}

	// Publish samples for the analysis pipeline (baselines, anomaly detection).
	m.a.publishSamples(now, sample{Metric: database.MetricLatencyMS, Value: msOf(agg.Avg), Valid: agg.Responded > 0},
		sample{Metric: database.MetricJitterMS, Value: msOf(agg.Jitter), Valid: agg.Responded > 0},
		sample{Metric: database.MetricPacketLossPct, Value: agg.LossPct, Valid: agg.Targets > 0})

	m.reportLoss(ctx, agg, now)
	return nil
}

// reportLoss raises the absolute-threshold packet-loss event. Baseline-relative
// degradation is handled by the anomaly detectors; this is the "loss is simply too high"
// rule, which needs no history to be meaningful.
func (m *latencyMonitor) reportLoss(ctx context.Context, agg latency.Aggregate, now time.Time) {
	threshold := m.a.cfg.Alerts.PacketLossPercent
	if threshold <= 0 || agg.Targets == 0 {
		return
	}
	// Loss is only meaningful when at least one target answered; a total failure is an
	// outage, reported by the connectivity monitor, not a loss event.
	if agg.Responded == 0 {
		return
	}

	d := m.loss.Observe("packet-loss", agg.LossPct >= threshold, now)
	switch {
	case d.Fire:
		var sent, recv int
		var target string
		for _, r := range agg.Results {
			sent += r.Sent
			recv += r.Recv
			if r.LossPct > 0 && target == "" {
				target = r.Target
			}
		}
		baseline, _, _ := m.a.db.LatestMeasurement(ctx, database.MetricPacketLossPct, "")
		m.a.log.Emit(events.New(events.PacketLossDetected).
			WithFields(events.Fields{}.
				AddPercent("PacketLoss", agg.LossPct).
				AddPercent("Threshold", threshold).
				AddPercent("BaselineLoss", baseline.Value).
				Add("Sent", sent).
				Add("Received", recv).
				Add("Target", target).
				AddUnit("Latency", msOf(agg.Avg), "ms").
				Add("Method", string(agg.Method)).
				Add("Consecutive", d.Consecutive)))
	case d.Recovered:
		m.a.log.Emit(events.New(events.PacketLossCleared).
			WithFields(events.Fields{}.
				AddPercent("PacketLoss", agg.LossPct).
				AddDuration("Duration", d.Duration).
				Add("Method", string(agg.Method))))
	}
}

func msOf(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
