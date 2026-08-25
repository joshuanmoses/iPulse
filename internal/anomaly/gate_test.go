package anomaly

import (
	"math"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/baseline"
)

func TestGatePersistence(t *testing.T) {
	g := NewGate(3, 2, 0)
	now := time.Now()

	for i := 1; i <= 2; i++ {
		d := g.Breach("k", now.Add(time.Duration(i)*time.Second))
		if d.Fire {
			t.Fatalf("fired after %d breaches, persistence is 3", i)
		}
		if d.Consecutive != i {
			t.Errorf("consecutive = %d, want %d", d.Consecutive, i)
		}
	}
	d := g.Breach("k", now.Add(3*time.Second))
	if !d.Fire {
		t.Fatal("expected fire on the third consecutive breach")
	}
	if !d.Firing {
		t.Error("expected the gate to report firing")
	}
	if d.Duration < 2*time.Second {
		t.Errorf("duration = %v, want at least 2s", d.Duration)
	}
}

func TestGateCooldownSuppressesRepeats(t *testing.T) {
	g := NewGate(1, 1, 10*time.Minute)
	now := time.Now()

	if d := g.Breach("k", now); !d.Fire {
		t.Fatal("expected the first breach to fire")
	}
	for i := 1; i <= 5; i++ {
		d := g.Breach("k", now.Add(time.Duration(i)*time.Minute))
		if d.Fire {
			t.Errorf("fired again %d minutes into a 10 minute cooldown", i)
		}
		if !d.Suppressed {
			t.Errorf("expected the repeat at +%dm to be reported as suppressed", i)
		}
	}
	// After the cooldown the condition is reported again, because it is still true.
	if d := g.Breach("k", now.Add(11*time.Minute)); !d.Fire {
		t.Error("expected a repeat after the cooldown expired")
	}
}

func TestGateZeroCooldownFiresOnce(t *testing.T) {
	g := NewGate(1, 1, 0)
	now := time.Now()
	if d := g.Breach("k", now); !d.Fire {
		t.Fatal("expected the first breach to fire")
	}
	// With no cooldown the event is reported once until it recovers, rather than on
	// every observation.
	for i := 1; i <= 3; i++ {
		if d := g.Breach("k", now.Add(time.Duration(i)*time.Minute)); d.Fire {
			t.Errorf("repeat %d fired with no cooldown configured", i)
		}
	}
}

func TestGateRecovery(t *testing.T) {
	g := NewGate(2, 3, 0)
	now := time.Now()
	g.Breach("k", now)
	g.Breach("k", now.Add(time.Second))
	if !g.Firing("k") {
		t.Fatal("expected the gate to be firing")
	}

	for i := 1; i <= 2; i++ {
		d := g.Clear("k", now.Add(time.Duration(i+1)*time.Second))
		if d.Recovered {
			t.Fatalf("recovered after %d clears, recovery persistence is 3", i)
		}
	}
	d := g.Clear("k", now.Add(10*time.Second))
	if !d.Recovered {
		t.Fatal("expected recovery on the third consecutive clear")
	}
	if d.Duration < 9*time.Second {
		t.Errorf("recovery duration = %v, expected the whole firing period", d.Duration)
	}
	if g.Firing("k") {
		t.Error("gate should no longer be firing")
	}
	// A clear when nothing was firing must not report a recovery.
	if d := g.Clear("k", now.Add(20*time.Second)); d.Recovered {
		t.Error("recovery reported without a preceding breach")
	}
}

// TestGateFlapping is the property the gate exists for: alternating observations must
// produce neither events nor recoveries.
func TestGateFlapping(t *testing.T) {
	g := NewGate(3, 3, time.Minute)
	now := time.Now()
	for i := 0; i < 20; i++ {
		d := g.Observe("k", i%2 == 0, now.Add(time.Duration(i)*time.Second))
		if d.Fire || d.Recovered {
			t.Fatalf("flapping produced an event at step %d: %+v", i, d)
		}
	}
}

func TestGateKeysAreIndependent(t *testing.T) {
	g := NewGate(1, 1, 0)
	now := time.Now()
	if d := g.Breach("a", now); !d.Fire {
		t.Fatal("key a should fire")
	}
	if g.Firing("b") {
		t.Error("key b must be unaffected")
	}
	if d := g.Breach("b", now); !d.Fire {
		t.Error("key b should fire independently")
	}
	if len(g.Keys()) != 2 {
		t.Errorf("keys = %v", g.Keys())
	}
	g.Reset("a")
	if g.Firing("a") {
		t.Error("reset should clear the key")
	}
}

func TestGatePruneKeepsFiringKeys(t *testing.T) {
	g := NewGate(1, 5, 0)
	now := time.Now()
	g.Breach("firing", now)
	g.Breach("stale", now)
	g.Clear("stale", now)
	g.Clear("stale", now)
	g.Clear("stale", now)
	g.Clear("stale", now)
	g.Clear("stale", now) // recovered, so no longer firing

	g.Prune(now.Add(time.Hour))
	keys := g.Keys()
	if len(keys) != 1 || keys[0] != "firing" {
		t.Errorf("prune kept %v, want only the firing key", keys)
	}
}

func TestGateNormalisesThresholds(t *testing.T) {
	g := NewGate(0, -1, 0)
	if d := g.Breach("k", time.Now()); !d.Fire {
		t.Error("persistence below 1 should behave as 1")
	}
}

func TestDeviationRuleAbove(t *testing.T) {
	g := NewGate(1, 1, 0)
	r := NewDeviationRule("latency_ms", Above, 100, 30, true, g)
	b := usableBaseline("latency_ms", 18, 18, 2, 60)
	now := time.Now()

	// 73 ms against an 18 ms baseline is a 305 % deviation: the documented example.
	f, ok := r.Evaluate(b, 73, "", now)
	if !ok || f.Recovered {
		t.Fatalf("expected a finding, got %+v ok=%v", f, ok)
	}
	if math.Abs(f.DeviationPct-305.55) > 0.1 {
		t.Errorf("deviation = %.2f%%, want about 305%%", f.DeviationPct)
	}
	if f.Baseline != 18 || f.Value != 73 {
		t.Errorf("finding values wrong: %+v", f)
	}
	if f.Observations != 60 {
		t.Errorf("observations = %d, want 60", f.Observations)
	}

	// Recovery is reported once.
	f, ok = r.Evaluate(b, 19, "", now.Add(time.Minute))
	if !ok || !f.Recovered {
		t.Errorf("expected a recovery finding, got %+v ok=%v", f, ok)
	}
}

// TestDeviationRuleMinAbsolute is the guard that stops a fast link from being reported
// as degraded for a movement that does not matter.
func TestDeviationRuleMinAbsolute(t *testing.T) {
	g := NewGate(1, 1, 0)
	r := NewDeviationRule("latency_ms", Above, 100, 30, true, g)
	b := usableBaseline("latency_ms", 5, 5, 1, 60)

	// 12 ms against a 5 ms baseline is a 140 % deviation, but 12 ms is not a problem.
	if _, ok := r.Evaluate(b, 12, "", time.Now()); ok {
		t.Error("a small absolute latency must not be reported however large the ratio")
	}
	// Once the absolute value matters, it is reported.
	if _, ok := r.Evaluate(b, 45, "", time.Now()); !ok {
		t.Error("expected a finding once the absolute value crossed the floor")
	}
}

func TestDeviationRuleBelow(t *testing.T) {
	g := NewGate(1, 1, 0)
	r := NewDeviationRule("download_mbps", Below, 40, 5, true, g)
	b := usableBaseline("download_mbps", 480, 480, 20, 40)

	// 200 Mbps against a 480 Mbps baseline is a 58 % shortfall.
	f, ok := r.Evaluate(b, 200, "", time.Now())
	if !ok {
		t.Fatal("expected a throughput degradation finding")
	}
	if f.DeviationPct > -40 {
		t.Errorf("deviation = %v%%, expected a large negative value", f.DeviationPct)
	}
	// A drop within the threshold is not a breach; because the rule was firing, this
	// observation clears it, which is reported as a recovery rather than as a new finding.
	f2, ok := r.Evaluate(b, 400, "", time.Now())
	if ok && !f2.Recovered {
		t.Errorf("a 17 %% drop must not breach a 40 %% threshold: %+v", f2)
	}
	// A fresh rule with no prior breach reports nothing at all.
	fresh := NewDeviationRule("download_mbps", Below, 40, 5, true, NewGate(1, 1, 0))
	if _, ok := fresh.Evaluate(b, 400, "", time.Now()); ok {
		t.Error("a 17 %% drop must produce no finding at all")
	}
}

func TestDeviationRuleIgnoresUnusableBaseline(t *testing.T) {
	g := NewGate(1, 1, 0)
	r := NewDeviationRule("latency_ms", Above, 100, 0, true, g)
	unusable := baseline.Baseline{
		Key: baseline.Key{Metric: "latency_ms"}, Samples: 3, Mean: 18, Median: 18, Established: false,
	}
	if _, ok := r.Evaluate(unusable, 500, "", time.Now()); ok {
		t.Error("an unestablished baseline must never produce a finding")
	}
}

func TestZScoreRule(t *testing.T) {
	g := NewGate(1, 1, 0)
	r := NewZScoreRule("tx_bps", 6, 5e6, Above, g)
	// A steady 2 Mbps upload with a small deviation.
	b := usableBaseline("tx_bps", 2e6, 2e6, 100e3, 200)

	// 94 Mbps is far outside the normal range and above the absolute floor.
	f, ok := r.Evaluate(b, 94e6, "eth0", time.Now())
	if !ok {
		t.Fatal("expected a spike finding")
	}
	if f.ZScore < 6 {
		t.Errorf("z-score = %v, want at least 6", f.ZScore)
	}
	if f.Dimension != "eth0" {
		t.Errorf("dimension = %q", f.Dimension)
	}

	// A statistically large but practically tiny spike is suppressed by the absolute
	// floor. A fresh rule is used so the previous breach cannot turn this into a
	// recovery report.
	quiet := usableBaseline("tx_bps", 1e3, 1e3, 50, 200)
	fresh := NewZScoreRule("tx_bps", 6, 5e6, Above, NewGate(1, 1, 0))
	if f, ok := fresh.Evaluate(quiet, 1e6, "eth0", time.Now()); ok {
		t.Errorf("a 1 Mbps spike on an idle link must not be reported: %+v", f)
	}
}

func TestSustainedRule(t *testing.T) {
	r := NewSustainedRule("tx_bps", 2e6, 2*time.Minute, 0)
	start := time.Now()

	// Below the floor: nothing happens.
	if _, ok := r.Observe("eth0", 1e6, start); ok {
		t.Error("a value below the floor must not report")
	}
	// Above the floor but not yet for long enough.
	for i := 0; i < 5; i++ {
		at := start.Add(time.Duration(i*20) * time.Second)
		if _, ok := r.Observe("eth0", 10e6, at); ok {
			t.Fatalf("reported after %v, minimum duration is 2m", at.Sub(start))
		}
	}
	// Past the minimum duration.
	f, ok := r.Observe("eth0", 20e6, start.Add(3*time.Minute))
	if !ok {
		t.Fatal("expected a sustained finding")
	}
	if f.Duration < 2*time.Minute {
		t.Errorf("duration = %v", f.Duration)
	}
	if f.Peak != 20e6 {
		t.Errorf("peak = %v, want 20 Mbps", f.Peak)
	}
	if f.Average < 10e6 {
		t.Errorf("average = %v, expected the whole period to be averaged", f.Average)
	}
	if f.Ended {
		t.Error("the condition has not ended")
	}

	// With Repeat unset it is reported once while it continues.
	if _, ok := r.Observe("eth0", 20e6, start.Add(4*time.Minute)); ok {
		t.Error("an ongoing condition must not be reported repeatedly")
	}
	// The end is reported.
	f, ok = r.Observe("eth0", 0, start.Add(5*time.Minute))
	if !ok || !f.Ended {
		t.Errorf("expected an end finding, got %+v ok=%v", f, ok)
	}
	if _, active := r.Active("eth0"); active {
		t.Error("state should be cleared after the condition ends")
	}
}

// TestSustainedRuleBriefBurstIsSilent is the whole point of the minimum duration: a
// single large transfer must not produce an event.
func TestSustainedRuleBriefBurstIsSilent(t *testing.T) {
	r := NewSustainedRule("tx_bps", 2e6, 2*time.Minute, 0)
	start := time.Now()
	r.Observe("eth0", 50e6, start)
	r.Observe("eth0", 50e6, start.Add(30*time.Second))
	if f, ok := r.Observe("eth0", 0, start.Add(45*time.Second)); ok {
		t.Errorf("a 45 second burst must produce no event, got %+v", f)
	}
}

func TestSustainedRuleRepeat(t *testing.T) {
	r := NewSustainedRule("tx_bps", 1e6, time.Minute, 5*time.Minute)
	start := time.Now()
	r.Observe("eth0", 10e6, start)
	if _, ok := r.Observe("eth0", 10e6, start.Add(90*time.Second)); !ok {
		t.Fatal("expected the first report")
	}
	if _, ok := r.Observe("eth0", 10e6, start.Add(3*time.Minute)); ok {
		t.Error("a repeat before the repeat interval must be suppressed")
	}
	if _, ok := r.Observe("eth0", 10e6, start.Add(7*time.Minute)); !ok {
		t.Error("expected a repeat after the repeat interval")
	}
}

func TestQuietHours(t *testing.T) {
	day := QuietHours{Start: 1, End: 6}
	if !day.Contains(time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)) {
		t.Error("03:00 should be inside 01:00-06:00")
	}
	if day.Contains(time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)) {
		t.Error("14:00 should be outside 01:00-06:00")
	}

	// A window that wraps midnight.
	night := QuietHours{Start: 22, End: 6}
	for _, hour := range []int{22, 23, 0, 3, 5} {
		if !night.Contains(time.Date(2026, 8, 24, hour, 0, 0, 0, time.UTC)) {
			t.Errorf("%02d:00 should be inside 22:00-06:00", hour)
		}
	}
	for _, hour := range []int{6, 12, 21} {
		if night.Contains(time.Date(2026, 8, 24, hour, 0, 0, 0, time.UTC)) {
			t.Errorf("%02d:00 should be outside 22:00-06:00", hour)
		}
	}
	if (QuietHours{Start: 0, End: 0}).Contains(time.Now()) {
		t.Error("an empty window must contain nothing")
	}
	if got := night.Describe(); got != "22:00-06:00" {
		t.Errorf("Describe = %q", got)
	}
}

// usableBaseline builds an established baseline for rule tests.
func usableBaseline(metric string, mean, median, mad float64, samples int64) baseline.Baseline {
	return baseline.Baseline{
		Key:         baseline.Key{Metric: metric, Bucket: "wd-14"},
		Samples:     samples,
		Mean:        mean,
		Median:      median,
		MAD:         mad,
		Min:         median - mad,
		Max:         median + mad,
		Established: true,
	}
}
