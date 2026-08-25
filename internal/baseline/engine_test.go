package baseline

import (
	"math"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{MinObservations: 10, TimeBuckets: true, BucketHours: 1, EWMAAlpha: 0.2, WindowSize: 64}
}

func TestBucketLabels(t *testing.T) {
	e := New(testConfig())
	// 2026-08-24 is a Monday.
	monday := time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC)
	saturday := time.Date(2026, 8, 29, 3, 5, 0, 0, time.UTC)

	if got := e.BucketFor(monday); got != "wd-14" {
		t.Errorf("weekday bucket = %q, want wd-14", got)
	}
	if got := e.BucketFor(saturday); got != "we-03" {
		t.Errorf("weekend bucket = %q, want we-03", got)
	}

	// Wider buckets group hours.
	cfg := testConfig()
	cfg.BucketHours = 6
	wide := New(cfg)
	if got := wide.BucketFor(monday); got != "wd-12" {
		t.Errorf("6-hour bucket = %q, want wd-12", got)
	}

	// Time bucketing can be turned off entirely.
	cfg2 := testConfig()
	cfg2.TimeBuckets = false
	flat := New(cfg2)
	if got := flat.BucketFor(monday); got != "all" {
		t.Errorf("flat bucket = %q, want all", got)
	}
}

// TestObserveReturnsPriorState is the property detectors depend on: a sample must be
// compared with the history that existed before it, not with a baseline it just moved.
func TestObserveReturnsPriorState(t *testing.T) {
	e := New(testConfig())
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		e.Observe("latency_ms", "", 20, at)
	}
	prior, _ := e.Observe("latency_ms", "", 500, at)
	if prior.Samples != 5 {
		t.Errorf("prior samples = %d, want 5", prior.Samples)
	}
	if prior.Mean != 20 {
		t.Errorf("prior mean = %v, want 20 (the outlier must not be included)", prior.Mean)
	}
	after, _ := e.Get("latency_ms", "", at)
	if after.Samples != 6 {
		t.Errorf("stored samples = %d, want 6", after.Samples)
	}
}

// TestNotEstablishedUntilMinObservations is the primary false-positive guard.
func TestNotEstablishedUntilMinObservations(t *testing.T) {
	e := New(testConfig())
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 9; i++ {
		e.Observe("latency_ms", "", 20, at)
		b, _ := e.Get("latency_ms", "", at)
		if b.Usable() {
			t.Fatalf("baseline became usable after %d samples, minimum is 10", i+1)
		}
	}
	_, established := e.Observe("latency_ms", "", 20, at)
	if !established {
		t.Fatal("expected the baseline to become established on the tenth sample")
	}
	b, _ := e.Get("latency_ms", "", at)
	if !b.Usable() {
		t.Error("baseline should be usable")
	}
	// Establishment is reported exactly once.
	newly := e.TakeNewlyEstablished()
	if len(newly) != 1 || newly[0].Metric != "latency_ms" {
		t.Errorf("newly established = %+v", newly)
	}
	if len(e.TakeNewlyEstablished()) != 0 {
		t.Error("establishment must be reported only once")
	}
}

func TestStatisticsAreCorrect(t *testing.T) {
	e := New(testConfig())
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	values := []float64{10, 12, 14, 16, 18, 20, 22, 24, 26, 28}
	for _, v := range values {
		e.Observe("latency_ms", "", v, at)
	}
	b, _ := e.Get("latency_ms", "", at)

	if b.Samples != 10 {
		t.Errorf("samples = %d", b.Samples)
	}
	if math.Abs(b.Mean-19) > 1e-9 {
		t.Errorf("mean = %v, want 19", b.Mean)
	}
	if b.Min != 10 || b.Max != 28 {
		t.Errorf("range = %v-%v", b.Min, b.Max)
	}
	if math.Abs(b.Median-19) > 1e-9 {
		t.Errorf("median = %v, want 19", b.Median)
	}
	if math.Abs(b.StdDev()-6.0553007081949835) > 1e-9 {
		t.Errorf("stddev = %v", b.StdDev())
	}
	if b.MAD <= 0 {
		t.Error("expected a positive median absolute deviation")
	}
}

// TestTimeBucketsAreIndependent is the reason the buckets exist: a busy afternoon must
// not raise the baseline for a quiet night.
func TestTimeBucketsAreIndependent(t *testing.T) {
	e := New(testConfig())
	afternoon := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	night := time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		e.Observe("tx_bps", "eth0", 50e6, afternoon)
		e.Observe("tx_bps", "eth0", 1e6, night)
	}
	day, _ := e.Get("tx_bps", "eth0", afternoon)
	dark, _ := e.Get("tx_bps", "eth0", night)

	if math.Abs(day.Mean-50e6) > 1 {
		t.Errorf("afternoon mean = %v", day.Mean)
	}
	if math.Abs(dark.Mean-1e6) > 1 {
		t.Errorf("night mean = %v", dark.Mean)
	}
	// The aggregate spans both, which is what the fallback uses.
	agg, ok := e.GetAggregate("tx_bps", "eth0")
	if !ok || agg.Samples != 40 {
		t.Errorf("aggregate = %+v ok=%v", agg, ok)
	}
	if agg.Mean < 20e6 || agg.Mean > 30e6 {
		t.Errorf("aggregate mean = %v, want about 25.5 Mbps", agg.Mean)
	}
}

// TestBestFallsBackToAggregate lets detection work in the first hours, before every
// hour-of-day bucket has filled.
func TestBestFallsBackToAggregate(t *testing.T) {
	e := New(testConfig())
	base := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)

	// Two samples in each of twelve different hours: no single bucket is established,
	// but there is plenty of aggregate history.
	for hour := 0; hour < 12; hour++ {
		at := base.Add(time.Duration(hour) * time.Hour)
		e.Observe("latency_ms", "", 20, at)
		e.Observe("latency_ms", "", 22, at)
	}
	at := base.Add(5 * time.Hour)
	if b, ok := e.Get("latency_ms", "", at); ok && b.Usable() {
		t.Fatal("no individual bucket should be established yet")
	}
	best, ok := e.Best("latency_ms", "", at)
	if !ok || !best.Usable() {
		t.Fatalf("expected the aggregate fallback to be usable: %+v", best)
	}
	if best.Bucket != "aggregate" {
		t.Errorf("fallback bucket = %q", best.Bucket)
	}
	if best.Samples != 24 {
		t.Errorf("aggregate samples = %d, want 24", best.Samples)
	}
}

func TestEWMATracksRecentChange(t *testing.T) {
	e := New(testConfig())
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		e.Observe("latency_ms", "", 20, at)
	}
	for i := 0; i < 20; i++ {
		e.Observe("latency_ms", "", 80, at)
	}
	b, _ := e.Get("latency_ms", "", at)
	// The mean is dragged down by the long history; the EWMA has followed the change.
	if b.EWMA < 60 {
		t.Errorf("EWMA = %v, expected it to follow the shift toward 80", b.EWMA)
	}
	if b.Mean > 50 {
		t.Errorf("mean = %v, expected the long history to dominate it", b.Mean)
	}
}

func TestWindowIsBounded(t *testing.T) {
	cfg := testConfig()
	cfg.WindowSize = 32
	e := New(cfg)
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 500; i++ {
		e.Observe("rx_bps", "eth0", float64(i), at)
	}
	rows := e.TakeDirty()
	if len(rows) != 1 {
		t.Fatalf("dirty rows = %d", len(rows))
	}
	// The persisted window must be bounded even after many samples.
	if len(rows[0].Window) > 1024 {
		t.Errorf("persisted window is %d bytes; it should be bounded", len(rows[0].Window))
	}
	b, _ := e.Get("rx_bps", "eth0", at)
	// The median reflects the recent window, not the whole history.
	if b.Median < 400 {
		t.Errorf("median = %v, expected it to reflect recent samples", b.Median)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	e := New(testConfig())
	at := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		e.Observe("latency_ms", "1.1.1.1", float64(18+i%4), at)
	}
	rows := e.TakeDirty()
	if len(rows) != 1 {
		t.Fatalf("expected one dirty row, got %d", len(rows))
	}
	if len(e.TakeDirty()) != 0 {
		t.Error("dirty set should be cleared after being taken")
	}

	restored := New(testConfig())
	restored.Load(rows)
	b, ok := restored.Get("latency_ms", "1.1.1.1", at)
	if !ok {
		t.Fatal("baseline not restored")
	}
	if b.Samples != 20 || !b.Usable() {
		t.Errorf("restored baseline = %+v", b)
	}
	if b.Median == 0 {
		t.Error("restored baseline lost its robust statistics")
	}
	// Continuing to observe after a restore must extend the same history.
	prior, _ := restored.Observe("latency_ms", "1.1.1.1", 19, at)
	if prior.Samples != 20 {
		t.Errorf("prior samples after restore = %d, want 20", prior.Samples)
	}
}

// TestLoadReappliesMinObservations means raising min_observations in configuration takes
// effect on restart rather than being masked by the stored flag.
func TestLoadReappliesMinObservations(t *testing.T) {
	e := New(testConfig())
	at := time.Now()
	for i := 0; i < 15; i++ {
		e.Observe("latency_ms", "", 20, at)
	}
	rows := e.TakeDirty()

	strict := testConfig()
	strict.MinObservations = 100
	restored := New(strict)
	restored.Load(rows)
	b, _ := restored.Get("latency_ms", "", at)
	if b.Usable() {
		t.Error("a stricter min_observations must make a restored baseline unusable")
	}
}

func TestPruneDropsStaleBuckets(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAge = time.Hour
	e := New(cfg)
	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now()

	e.Observe("latency_ms", "old", 20, old)
	e.Observe("latency_ms", "new", 20, recent)

	if removed := e.Prune(time.Now()); removed != 1 {
		t.Errorf("pruned %d buckets, want 1", removed)
	}
	total, _ := e.Count()
	if total != 1 {
		t.Errorf("remaining baselines = %d", total)
	}
}

func TestInvalidValuesAreIgnored(t *testing.T) {
	e := New(testConfig())
	at := time.Now()
	e.Observe("latency_ms", "", math.NaN(), at)
	e.Observe("latency_ms", "", math.Inf(1), at)
	if total, _ := e.Count(); total != 0 {
		t.Error("NaN and infinity must not create a baseline")
	}
}

func TestCountAndMetrics(t *testing.T) {
	e := New(testConfig())
	at := time.Now()
	for i := 0; i < 12; i++ {
		e.Observe("latency_ms", "", 20, at)
	}
	e.Observe("jitter_ms", "", 2, at)

	total, established := e.Count()
	if total != 2 || established != 1 {
		t.Errorf("count = %d total, %d established", total, established)
	}
	metrics := e.Metrics()
	if len(metrics) != 2 || metrics[0] != "jitter_ms" {
		t.Errorf("metrics = %v", metrics)
	}
}
