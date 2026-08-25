package agent

import (
	"context"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/latency"
)

// weekdayAfternoon is a fixed instant so the time-bucket behaviour is deterministic.
func weekdayAfternoon() time.Time {
	// 2026-08-24 is a Monday.
	return time.Date(2026, 8, 24, 14, 0, 0, 0, time.Local)
}

func weekdayNight() time.Time {
	return time.Date(2026, 8, 24, 3, 0, 0, 0, time.Local)
}

// TestSimulatePoorLatency reproduces the documented example: an 18 ms baseline rising to
// 73 ms must be reported as a latency degradation with the deviation stated.
func TestSimulatePoorLatency(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 2
	})
	start := weekdayAfternoon()

	// Establish a steady baseline. Slight variation is realistic and gives the robust
	// statistics something to work with.
	at := start
	for i := 0; i < 30; i++ {
		value := 18 + float64(i%3)
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: value, Valid: true})
		at = at.Add(30 * time.Second)
	}
	requireNoEvent(t, a, events.LatencyDegradation)

	// Now the degradation. Persistence is 2, so two consecutive breaches are needed.
	for i := 0; i < 3; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: 73, Valid: true})
		at = at.Add(30 * time.Second)
	}

	ev := requireEvent(t, a, events.LatencyDegradation)
	if ev.Fields["CurrentLatency"] != "73.0ms" {
		t.Errorf("CurrentLatency = %q", ev.Fields["CurrentLatency"])
	}
	baseline := ev.Fields["BaselineLatency"]
	if baseline != "19.0ms" && baseline != "18.0ms" && baseline != "20.0ms" {
		t.Errorf("BaselineLatency = %q, want about 19ms", baseline)
	}
	// The deviation is the number an operator reads first, so it must be right.
	dev, err := strconv.Atoi(strings.TrimSuffix(ev.Fields["Deviation"], "%"))
	if err != nil {
		t.Fatalf("Deviation = %q: %v", ev.Fields["Deviation"], err)
	}
	if dev < 250 || dev > 330 {
		t.Errorf("Deviation = %d%%, want about 284-305%%", dev)
	}
	if ev.Fields["ProbableCause"] == "" {
		t.Error("a latency degradation must state a probable cause")
	}
	if ev.Fields["Observations"] == "" || ev.Fields["Observations"] == "0" {
		t.Errorf("Observations = %q; the event must say how much history backs it", ev.Fields["Observations"])
	}

	// Recovery is reported once the metric returns.
	for i := 0; i < 4; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: 19, Valid: true})
		at = at.Add(30 * time.Second)
	}
	rec := requireEvent(t, a, events.PerformanceRecovered)
	if rec.Fields["Metric"] != "latency" {
		t.Errorf("recovery metric = %q", rec.Fields["Metric"])
	}
}

// TestSimulateSmallLatencyRiseIsIgnored is the false-positive guard: a proportionally
// large rise that is still a small absolute latency must not be reported.
func TestSimulateSmallLatencyRiseIsIgnored(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.MinAbsoluteLatencyMS = 30
	})
	at := feedRepeated(t, a, database.MetricLatencyMS, "", 5, 30, weekdayAfternoon(), 30*time.Second)

	// 12 ms against a 5 ms baseline is a 140 % deviation, but 12 ms is fine.
	for i := 0; i < 5; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: 12, Valid: true})
		at = at.Add(30 * time.Second)
	}
	requireNoEvent(t, a, events.LatencyDegradation)
}

// TestSimulateNoBaselineNoDetection is the primary guard against day-one false
// positives: without enough history nothing is anomalous.
func TestSimulateNoBaselineNoDetection(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 30
		c.Alerts.Persistence = 1
	})
	at := weekdayAfternoon()
	// Five quiet samples, then a huge jump. There is not enough history to judge it.
	for i := 0; i < 5; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: 18, Valid: true})
		at = at.Add(30 * time.Second)
	}
	for i := 0; i < 5; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricLatencyMS, Value: 900, Valid: true})
		at = at.Add(30 * time.Second)
	}
	requireNoEvent(t, a, events.LatencyDegradation)
	requireNoEvent(t, a, events.BaselineEstablished)
}

// TestSimulateBandwidthDegradation covers a throughput collapse against the learned
// baseline.
func TestSimulateBandwidthDegradation(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Alerts.DownloadDegradationPercent = 40
	})
	at := weekdayAfternoon()
	for i := 0; i < 25; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricDownloadMbps, Value: 480 + float64(i%5), Valid: true})
		at = at.Add(30 * time.Minute)
	}
	feed(t, a, sample{Time: at, Metric: database.MetricDownloadMbps, Value: 180, Valid: true})

	ev := requireEvent(t, a, events.DownloadDegradation)
	if ev.Fields["CurrentDownload"] != "180.0Mbps" {
		t.Errorf("CurrentDownload = %q", ev.Fields["CurrentDownload"])
	}
	if !strings.HasPrefix(ev.Fields["Deviation"], "-6") {
		t.Errorf("Deviation = %q, want about -62%%", ev.Fields["Deviation"])
	}
	if ev.Fields["ProbableCause"] == "" {
		t.Error("expected a probable cause")
	}
}

// TestSimulateUploadSaturation drives an upload spike far outside the learned range.
func TestSimulateUploadSaturation(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Traffic.SpikeZScore = 6
		c.Traffic.SpikeMinMbps = 5
	})
	at := weekdayAfternoon()
	// A steady 2 Mbps of background upload.
	for i := 0; i < 30; i++ {
		value := 2e6 + float64(i%4)*50e3
		feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: value, Valid: true})
		at = at.Add(5 * time.Second)
	}
	requireNoEvent(t, a, events.BandwidthSpikeUpload)

	// 94 Mbps: an upload saturating the link.
	feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: 94e6, Valid: true})

	ev := requireEvent(t, a, events.BandwidthSpikeUpload)
	if ev.Fields["Interface"] != "eth0" {
		t.Errorf("Interface = %q", ev.Fields["Interface"])
	}
	if ev.Fields["CurrentRate"] != "94.0Mbps" {
		t.Errorf("CurrentRate = %q", ev.Fields["CurrentRate"])
	}
	z, err := strconv.ParseFloat(ev.Fields["ZScore"], 64)
	if err != nil || z < 6 {
		t.Errorf("ZScore = %q, want at least 6", ev.Fields["ZScore"])
	}
}

// TestSimulateSpikeOnIdleLinkIsIgnored is the absolute-floor guard: a statistically
// enormous but practically irrelevant spike must stay quiet.
func TestSimulateSpikeOnIdleLinkIsIgnored(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Traffic.SpikeMinMbps = 5
	})
	at := weekdayAfternoon()
	for i := 0; i < 30; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0",
			Value: 1000 + float64(i%3), Valid: true})
		at = at.Add(5 * time.Second)
	}
	// 1 Mbps is a thousandfold increase, and still nothing worth reporting.
	feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: 1e6, Valid: true})
	requireNoEvent(t, a, events.BandwidthSpikeUpload)
}

// TestSimulateSustainedUpload is the "something has been uploading for a long time" case.
func TestSimulateSustainedUpload(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Traffic.SustainedUploadMbps = 2
		c.Alerts.SustainedUploadSeconds = 120
	})
	at := weekdayAfternoon()
	// Ten Mbps for five minutes, sampled every five seconds.
	for i := 0; i < 60; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: 10e6, Valid: true})
		at = at.Add(5 * time.Second)
	}
	ev := requireEvent(t, a, events.SustainedUpload)
	if ev.Fields["AverageRate"] != "10.0Mbps" {
		t.Errorf("AverageRate = %q", ev.Fields["AverageRate"])
	}
	if ev.Fields["Confidence"] == "" {
		t.Error("a sustained-upload event must state its confidence")
	}
	dur := ev.Fields["Duration"]
	if dur == "" || dur == "0s" {
		t.Errorf("Duration = %q", dur)
	}
}

// TestSimulateBriefUploadBurstIsQuiet is the corresponding negative: a short transfer
// must produce nothing.
func TestSimulateBriefUploadBurstIsQuiet(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Traffic.SustainedUploadMbps = 2
		c.Alerts.SustainedUploadSeconds = 120
	})
	at := weekdayAfternoon()
	for i := 0; i < 6; i++ { // 30 seconds
		feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: 50e6, Valid: true})
		at = at.Add(5 * time.Second)
	}
	feed(t, a, sample{Time: at, Metric: database.MetricTxBps, Target: "eth0", Value: 0, Valid: true})
	requireNoEvent(t, a, events.SustainedUpload)
}

// TestSimulateUnexpectedUploadVolume covers volume over a window rather than rate, which
// is what catches a transfer that finishes between rate samples.
func TestSimulateUnexpectedUploadVolume(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Traffic.SpikeZScore = 6
		c.Destinations.HighVolumeMB = 64
	})
	at := weekdayAfternoon()
	// A normal five-minute window carries a few megabytes.
	for i := 0; i < 30; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricTxBytesWindow, Target: "eth0",
			Value: 4<<20 + float64(i%3)*(1<<18), Valid: true})
		at = at.Add(time.Minute)
	}
	// Then two gigabytes in one window.
	feed(t, a, sample{Time: at, Metric: database.MetricTxBytesWindow, Target: "eth0",
		Value: 2 << 30, Valid: true})

	ev := requireEvent(t, a, events.UnusualOutboundTraffic)
	if ev.Fields["WindowBytes"] != "2.00GiB" {
		t.Errorf("WindowBytes = %q", ev.Fields["WindowBytes"])
	}
	// Attribution must be described honestly rather than asserted.
	if !strings.Contains(ev.Fields["Attribution"], "concurrency-based") {
		t.Errorf("Attribution = %q; it must state how the process was inferred", ev.Fields["Attribution"])
	}
	if ev.Fields["Confidence"] != "low" {
		t.Errorf("Confidence = %q", ev.Fields["Confidence"])
	}
	// The same volume also qualifies as a large transfer.
	requireEvent(t, a, events.LargeOutboundTransfer)
}

// TestSimulateOvernightActivity is the time-aware case: the same volume is unremarkable
// in the afternoon and notable at 3 AM.
func TestSimulateOvernightActivity(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Traffic.QuietHoursStart = 1
		c.Traffic.QuietHoursEnd = 6
		c.Destinations.HighVolumeMB = 64
	})
	at := weekdayNight()
	for i := 0; i < 30; i++ {
		feed(t, a, sample{Time: at, Metric: database.MetricTxBytesWindow, Target: "eth0",
			Value: 1<<20 + float64(i%3)*4096, Valid: true})
		at = at.Add(time.Minute)
	}
	feed(t, a, sample{Time: at, Metric: database.MetricTxBytesWindow, Target: "eth0",
		Value: 3 << 30, Valid: true})

	ev := requireEvent(t, a, events.UnusualOvernightTraffic)
	if ev.Fields["Window"] != "01:00-06:00" {
		t.Errorf("Window = %q", ev.Fields["Window"])
	}
	if ev.Fields["Direction"] != "upload" {
		t.Errorf("Direction = %q", ev.Fields["Direction"])
	}
	// The daytime event must not also fire for the same sample.
	requireNoEvent(t, a, events.UnusualOutboundTraffic)
}

// TestSimulateTimeAwareBaselines is the property that makes the buckets worth having: a
// value that is normal for the afternoon is anomalous at night.
func TestSimulateTimeAwareBaselines(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Baseline.MinObservations = 20
		c.Alerts.Persistence = 1
		c.Traffic.SpikeZScore = 5
		c.Traffic.SpikeMinMbps = 1
		// Quiet hours off, so this tests the bucketing rather than the overnight rule.
		c.Traffic.QuietHoursStart = 0
		c.Traffic.QuietHoursEnd = 0
	})

	// Afternoons carry 50 Mbps; nights carry 1 Mbps. Both baselines are built on the
	// same day-of-week so only the hour differs.
	afternoon := weekdayAfternoon()
	night := weekdayNight()
	for i := 0; i < 30; i++ {
		feed(t, a, sample{Time: afternoon, Metric: database.MetricRxBps, Target: "eth0",
			Value: 50e6 + float64(i%5)*1e5, Valid: true})
		feed(t, a, sample{Time: night, Metric: database.MetricRxBps, Target: "eth0",
			Value: 1e6 + float64(i%5)*1e4, Valid: true})
		afternoon = afternoon.Add(time.Second)
		night = night.Add(time.Second)
	}

	// 50 Mbps in the afternoon is business as usual.
	feed(t, a, sample{Time: afternoon, Metric: database.MetricRxBps, Target: "eth0", Value: 50e6, Valid: true})
	requireNoEvent(t, a, events.BandwidthSpikeDownload)

	// The same 50 Mbps at 3 AM is fifty times the night-time normal.
	feed(t, a, sample{Time: night, Metric: database.MetricRxBps, Target: "eth0", Value: 50e6, Valid: true})
	ev := requireEvent(t, a, events.BandwidthSpikeDownload)
	if !strings.HasPrefix(ev.Fields["Bucket"], "wd-0") {
		t.Errorf("Bucket = %q, expected an early-morning weekday bucket", ev.Fields["Bucket"])
	}
}

// TestSimulatePacketLoss drives the absolute packet-loss rule through the latency
// monitor, which is where the threshold detector lives.
func TestSimulatePacketLoss(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Alerts.PacketLossPercent = 2
		c.Alerts.Persistence = 2
	})
	lat := newLatencyMonitor(a)
	ctx := context.Background()
	now := weekdayAfternoon()

	lossy := latency.Aggregate{
		Method: latency.MethodICMP, Targets: 2, Responded: 2, LossPct: 6,
		Avg: 40 * time.Millisecond,
		Results: []latency.Result{
			{Target: "1.1.1.1", Sent: 5, Recv: 4, LossPct: 20},
			{Target: "8.8.8.8", Sent: 5, Recv: 5},
		},
	}
	// Persistence is 2, so one cycle is not enough.
	lat.reportLoss(ctx, lossy, now)
	requireNoEvent(t, a, events.PacketLossDetected)

	lat.reportLoss(ctx, lossy, now.Add(30*time.Second))
	ev := requireEvent(t, a, events.PacketLossDetected)
	if ev.Fields["PacketLoss"] != "6.0%" {
		t.Errorf("PacketLoss = %q", ev.Fields["PacketLoss"])
	}
	if ev.Fields["Sent"] != "10" || ev.Fields["Received"] != "9" {
		t.Errorf("probe counts wrong: sent=%q received=%q", ev.Fields["Sent"], ev.Fields["Received"])
	}

	// Loss clearing is reported once.
	clean := latency.Aggregate{Method: latency.MethodICMP, Targets: 2, Responded: 2, LossPct: 0}
	for i := 0; i < 4; i++ {
		lat.reportLoss(ctx, clean, now.Add(time.Duration(60+i*30)*time.Second))
	}
	requireEvent(t, a, events.PacketLossCleared)
}

// TestSimulateTotalLossIsNotAPacketLossEvent keeps the taxonomy clean: a complete
// failure is an outage, reported by the connectivity monitor, not a loss event.
func TestSimulateTotalLossIsNotAPacketLossEvent(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Alerts.PacketLossPercent = 2
		c.Alerts.Persistence = 1
	})
	lat := newLatencyMonitor(a)
	down := latency.Aggregate{Method: latency.MethodICMP, Targets: 2, Responded: 0, LossPct: 100}
	lat.reportLoss(context.Background(), down, weekdayAfternoon())
	requireNoEvent(t, a, events.PacketLossDetected)
}

// TestSimulateBaselineEstablishedIsReportedOnce documents when detection becomes active.
func TestSimulateBaselineEstablishedIsReportedOnce(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) { c.Baseline.MinObservations = 10 })
	at := feedRepeated(t, a, database.MetricLatencyMS, "", 20, 15, weekdayAfternoon(), 30*time.Second)
	_ = at

	list := findEvents(t, a, events.BaselineEstablished)
	if len(list) != 1 {
		t.Fatalf("expected exactly one establishment event, got %d", len(list))
	}
	if list[0].Fields["Metric"] != database.MetricLatencyMS {
		t.Errorf("Metric = %q", list[0].Fields["Metric"])
	}
	if list[0].Fields["Observations"] != "10" {
		t.Errorf("Observations = %q, want 10", list[0].Fields["Observations"])
	}
}

// TestSimulateBaselinesSurviveRestart checks that learned history is not thrown away,
// which would otherwise reopen the day-one false-positive window on every restart.
func TestSimulateBaselinesSurviveRestart(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) { c.Baseline.MinObservations = 20 })
	feedRepeated(t, a, database.MetricLatencyMS, "", 18, 30, weekdayAfternoon(), 30*time.Second)

	if err := a.anomaly.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	total, established := a.anomaly.Baselines().Count()
	if total == 0 || established == 0 {
		t.Fatalf("expected established baselines before restart: %d/%d", established, total)
	}

	// A second engine loading the same rows must see the same history.
	restored := newAnomalyMonitor(a)
	if err := restored.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	rTotal, rEstablished := restored.Baselines().Count()
	if rTotal != total || rEstablished != established {
		t.Errorf("restored %d/%d baselines, want %d/%d", rEstablished, rTotal, established, total)
	}
	b, ok := restored.Baselines().Get(database.MetricLatencyMS, "", weekdayAfternoon())
	if !ok || math.Abs(b.Mean-18) > 0.001 {
		t.Errorf("restored baseline mean = %v, want 18", b.Mean)
	}
}
