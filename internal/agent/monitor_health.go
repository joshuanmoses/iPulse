package agent

import (
	"context"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/health"
)

// healthMonitor computes the Internet Health Score from what has actually been measured.
//
// Inputs come from the stored measurements over the configured window rather than the
// latest single reading, so one bad probe cannot move the score and a recovering
// connection climbs back gradually.
type healthMonitor struct {
	a    *Agent
	gate *gate
}

func newHealthMonitor(a *Agent) *healthMonitor {
	return &healthMonitor{a: a, gate: a.newGate()}
}

func (m *healthMonitor) Name() string { return "health" }

func (m *healthMonitor) Tasks() []Task {
	return []Task{{
		Name:         "health-score",
		Interval:     m.a.cfg.Monitoring.HealthScoreInterval.D(),
		Timeout:      30 * time.Second,
		InitialDelay: 30 * time.Second,
		RunOnStart:   true,
		Fn:           m.run,
	}}
}

func (m *healthMonitor) run(ctx context.Context) error {
	cfg := m.a.cfg.Health
	if !cfg.Enabled {
		return nil
	}
	now := time.Now()
	window := cfg.Window.D()
	since := now.Add(-window)

	in := health.Inputs{
		ExpectedDownload: m.a.cfg.SpeedTest.ExpectedDownloadMbps,
		ExpectedUpload:   m.a.cfg.SpeedTest.ExpectedUploadMbps,
	}

	if av, err := m.a.db.AvailabilitySince(ctx, since); err == nil {
		in.AvailabilityPct, in.HaveAvailability = av.Percent, true
	}
	// Medians, not means: a single spike should not define the score.
	if stats, err := m.a.db.MetricStats(ctx, database.MetricLatencyMS, "", since, now); err == nil && stats.Count > 0 {
		in.LatencyMS, in.HaveLatency = stats.Median, true
	}
	if stats, err := m.a.db.MetricStats(ctx, database.MetricJitterMS, "", since, now); err == nil && stats.Count > 0 {
		in.JitterMS, in.HaveJitter = stats.Median, true
	}
	if stats, err := m.a.db.MetricStats(ctx, database.MetricPacketLossPct, "", since, now); err == nil && stats.Count > 0 {
		// Loss uses the mean: a short burst of loss is a real quality problem, and the
		// median would hide it entirely.
		in.LossPct, in.HaveLoss = stats.Mean, true
	}
	if stats, err := m.a.db.MetricStats(ctx, database.MetricDNSMS, "", since, now); err == nil && stats.Count > 0 {
		in.DNSMS, in.HaveDNS = stats.Median, true
	}

	// Throughput comes from the last full test in a wider window: full tests are
	// deliberately infrequent, so a one-hour window would usually contain none.
	speedWindow := window
	if speedWindow < 6*time.Hour {
		speedWindow = 6 * time.Hour
	}
	if tests, err := m.a.db.QuerySpeedTests(ctx, database.SpeedModeFull, now.Add(-speedWindow), now, 20); err == nil {
		var dl, ul []float64
		for _, t := range tests {
			if t.Status == "ok" && t.DownloadMbps > 0 {
				dl = append(dl, t.DownloadMbps)
			}
			if t.Status == "ok" && t.UploadMbps > 0 {
				ul = append(ul, t.UploadMbps)
			}
		}
		if len(dl) > 0 {
			in.DownloadMbps, in.HaveDownload = medianOf(dl), true
		}
		if len(ul) > 0 {
			in.UploadMbps, in.HaveUpload = medianOf(ul), true
		}
	}

	score := health.Compute(in,
		health.Weights{
			Availability: cfg.Weights.Availability,
			Download:     cfg.Weights.Download,
			Upload:       cfg.Weights.Upload,
			Latency:      cfg.Weights.Latency,
			Jitter:       cfg.Weights.Jitter,
			PacketLoss:   cfg.Weights.PacketLoss,
			DNS:          cfg.Weights.DNS,
		},
		health.Thresholds{
			LatencyGoodMS: cfg.LatencyGoodMS, LatencyBadMS: cfg.LatencyBadMS,
			JitterGoodMS: cfg.JitterGoodMS, JitterBadMS: cfg.JitterBadMS,
			LossGoodPct: cfg.LossGoodPct, LossBadPct: cfg.LossBadPct,
			DNSGoodMS: cfg.DNSGoodMS, DNSBadMS: cfg.DNSBadMS,
		})

	if !score.Usable() {
		// Nothing measurable yet; do not publish a misleading zero.
		return nil
	}

	if err := m.a.db.InsertMeasurement(ctx, database.Measurement{
		Time: now, Metric: database.MetricHealthScore, Value: score.Total, Unit: "score", OK: true,
	}); err != nil {
		return err
	}
	m.a.state.Update(func(s *Snapshot) {
		s.HealthScore = score.Total
		s.HealthComponents = score.Components
	})
	m.a.publishSamples(now, sample{Metric: database.MetricHealthScore, Value: score.Total, Valid: true})

	m.a.log.Emit(events.New(events.HealthScoreUpdated).
		WithFields(events.Fields{}.
			AddUnitPrec("Score", score.Total, "", 1).
			AddPercent("Availability", in.AvailabilityPct).
			AddUnit("Download", in.DownloadMbps, "Mbps").
			AddUnit("Upload", in.UploadMbps, "Mbps").
			AddUnit("Latency", in.LatencyMS, "ms").
			AddUnit("Jitter", in.JitterMS, "ms").
			AddPercent("PacketLoss", in.LossPct).
			AddUnit("DNS", in.DNSMS, "ms")))

	d := m.gate.Observe("health-score", score.Total < cfg.WarnBelow, now)
	switch {
	case d.Fire:
		m.a.log.Emit(events.New(events.HealthScoreDegraded).
			WithFields(events.Fields{}.
				AddUnitPrec("Score", score.Total, "", 1).
				AddUnitPrec("Threshold", cfg.WarnBelow, "", 0).
				Add("WorstComponent", score.Worst).
				AddUnitPrec("WorstScore", score.WorstScore, "", 1).
				Add("ComponentScores", describeComponents(score)).
				Add("Grade", score.Grade())))
	case d.Recovered:
		m.a.log.Emit(events.New(events.HealthScoreUpdated).WithSeverity(events.Notice).
			WithFields(events.Fields{}.
				AddUnitPrec("Score", score.Total, "", 1).
				Add("Detail", "health score recovered above the warning threshold").
				AddDuration("Duration", d.Duration)))
	}
	return nil
}

// describeComponents renders the breakdown compactly, so the event itself shows why the
// score is what it is.
func describeComponents(s health.Score) string {
	names := make([]string, 0, len(s.Components))
	for n := range s.Components {
		names = append(names, n)
	}
	// Stable order: worst first is the most useful for an operator.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if s.Components[names[j]] < s.Components[names[i]] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+"="+trimScore(s.Components[n]))
	}
	return strings.Join(parts, " ")
}

func trimScore(v float64) string {
	if v == float64(int64(v)) {
		return itoa(int64(v))
	}
	return formatFloat1(v)
}

func medianOf(in []float64) float64 {
	sorted := append([]float64(nil), in...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
