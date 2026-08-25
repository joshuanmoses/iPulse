package latency

import (
	"context"
	"math"
	"net"
	"testing"
	"time"
)

func TestSummariseStatistics(t *testing.T) {
	res := Result{
		Target: "1.1.1.1", Method: MethodICMP, Sent: 5, Recv: 4,
		RTTs: []time.Duration{
			10 * time.Millisecond,
			14 * time.Millisecond,
			12 * time.Millisecond,
			20 * time.Millisecond,
		},
	}
	summarise(&res)

	if res.Min != 10*time.Millisecond || res.Max != 20*time.Millisecond {
		t.Errorf("range = %v-%v", res.Min, res.Max)
	}
	if res.Avg != 14*time.Millisecond {
		t.Errorf("avg = %v, want 14ms", res.Avg)
	}
	// Sorted: 10, 12, 14, 20 -> median is the mean of 12 and 14.
	if res.Median != 13*time.Millisecond {
		t.Errorf("median = %v, want 13ms", res.Median)
	}
	// Consecutive deltas: 4, 2, 8 -> mean 4.666ms
	if math.Abs(res.JitterMS()-4.6667) > 0.001 {
		t.Errorf("jitter = %v, want ~4.667ms", res.Jitter)
	}
	if res.LossPct != 20 {
		t.Errorf("loss = %v%%, want 20%%", res.LossPct)
	}
	if !res.OK() {
		t.Error("a result with received probes must report OK")
	}
}

func TestSummariseEdgeCases(t *testing.T) {
	// Total loss.
	res := Result{Sent: 4, Recv: 0}
	summarise(&res)
	if res.LossPct != 100 || res.Avg != 0 || res.OK() {
		t.Errorf("total loss mishandled: %+v", res)
	}
	// A single probe has no jitter.
	single := Result{Sent: 1, Recv: 1, RTTs: []time.Duration{7 * time.Millisecond}}
	summarise(&single)
	if single.Jitter != 0 || single.Median != 7*time.Millisecond {
		t.Errorf("single sample mishandled: %+v", single)
	}
	// No probes sent at all must not divide by zero.
	empty := Result{}
	summarise(&empty)
	if empty.LossPct != 0 {
		t.Errorf("empty result loss = %v", empty.LossPct)
	}
}

func TestMeanDeviation(t *testing.T) {
	// A perfectly steady link has no jitter.
	steady := []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	if got := meanDeviation(steady); got != 0 {
		t.Errorf("steady link jitter = %v, want 0", got)
	}
	// Alternating 10/20 gives a 10 ms mean deviation.
	alternating := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 10 * time.Millisecond}
	if got := meanDeviation(alternating); got != 10*time.Millisecond {
		t.Errorf("alternating jitter = %v, want 10ms", got)
	}
}

// TestAggregatePicksBestTarget is the property that keeps one rate-limiting target from
// being read as a degraded connection.
func TestAggregatePicksBestTarget(t *testing.T) {
	fast := Result{Target: "1.1.1.1", Method: MethodICMP, Sent: 4, Recv: 4,
		RTTs: []time.Duration{8 * time.Millisecond, 9 * time.Millisecond, 8 * time.Millisecond, 9 * time.Millisecond}}
	slow := Result{Target: "8.8.8.8", Method: MethodICMP, Sent: 4, Recv: 4,
		RTTs: []time.Duration{80 * time.Millisecond, 90 * time.Millisecond, 85 * time.Millisecond, 95 * time.Millisecond}}
	dead := Result{Target: "192.0.2.1", Method: MethodICMP, Sent: 4, Recv: 0}
	summarise(&fast)
	summarise(&slow)
	summarise(&dead)

	agg := Aggregate_([]Result{fast, slow, dead})
	if agg.Targets != 3 || agg.Responded != 2 {
		t.Errorf("counts wrong: %+v", agg)
	}
	if agg.Best != 8*time.Millisecond {
		t.Errorf("best = %v, want 8ms", agg.Best)
	}
	// 12 probes sent, 8 answered.
	if math.Abs(agg.LossPct-33.3333) > 0.001 {
		t.Errorf("aggregate loss = %v%%, want ~33.3%%", agg.LossPct)
	}
	if agg.Method != MethodICMP {
		t.Errorf("method = %v", agg.Method)
	}
}

func TestAggregateAllDown(t *testing.T) {
	dead := Result{Target: "192.0.2.1", Sent: 3, Recv: 0}
	summarise(&dead)
	agg := Aggregate_([]Result{dead})
	if agg.Responded != 0 || agg.LossPct != 100 || agg.Best != 0 {
		t.Errorf("all-down aggregate wrong: %+v", agg)
	}
}

func TestMethodSelection(t *testing.T) {
	// An explicit method is always honoured, even where ICMP is available.
	if p := New(Config{Method: MethodTCP}); p.Method() != MethodTCP {
		t.Errorf("explicit tcp not honoured: %v", p.Method())
	}
	if p := New(Config{Method: MethodICMP}); p.Method() != MethodICMP {
		t.Errorf("explicit icmp not honoured: %v", p.Method())
	}
	// Auto resolves to one of the two.
	if m := New(Config{Method: MethodAuto}).Method(); m != MethodICMP && m != MethodTCP {
		t.Errorf("auto resolved to %v", m)
	}
}

func TestDefaultsApplied(t *testing.T) {
	p := New(Config{})
	if p.cfg.Probes != 5 || p.cfg.Timeout != 2*time.Second || p.cfg.TCPPort != 443 {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
}

// TestTCPProbeAgainstLocalListener exercises the TCP path deterministically, with no
// dependency on the Internet.
func TestTCPProbeAgainstLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	p := New(Config{Method: MethodTCP, Probes: 3, Spacing: time.Millisecond, Timeout: time.Second})
	res := p.Probe(context.Background(), ln.Addr().String())
	if res.Recv != 3 || res.LossPct != 0 {
		t.Errorf("expected 3 successful handshakes, got %+v", res)
	}
	if res.Method != MethodTCP {
		t.Errorf("method = %v", res.Method)
	}
	if res.Avg <= 0 {
		t.Error("expected a positive round trip")
	}
}

// TestTCPProbeRefusedCountsAsReachable is the important behaviour: a closed port proves
// the host answered, so it must not be reported as packet loss.
func TestTCPProbeRefusedCountsAsReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	// Close it so connections are refused rather than accepted.
	_ = ln.Close()

	p := New(Config{Method: MethodTCP, Probes: 2, Spacing: time.Millisecond, Timeout: time.Second})
	res := p.Probe(context.Background(), addr)
	if res.Recv != 2 {
		t.Errorf("a refused connection must count as a response, got %+v", res)
	}
	if res.LossPct != 0 {
		t.Errorf("loss = %v%%, want 0%% for a refused port", res.LossPct)
	}
}

func TestProbeRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New(Config{Method: MethodTCP, Probes: 5, Spacing: time.Second, Timeout: time.Second})
	start := time.Now()
	res := p.Probe(ctx, "192.0.2.1:443")
	if time.Since(start) > 2*time.Second {
		t.Errorf("cancelled probe took %v", time.Since(start))
	}
	if res.Recv != 0 {
		t.Errorf("cancelled probe should not report responses: %+v", res)
	}
}

func TestICMPFilteredMemo(t *testing.T) {
	p := New(Config{Method: MethodAuto})
	if p.icmpFiltered("1.2.3.4") {
		t.Error("nothing should be marked filtered initially")
	}
	p.markICMPFiltered("1.2.3.4")
	if !p.icmpFiltered("1.2.3.4") {
		t.Error("target should be marked filtered")
	}
	if p.icmpFiltered("5.6.7.8") {
		t.Error("the memo must be per-target")
	}
	// Expiry.
	p.icmpBlocked["1.2.3.4"] = time.Now().Add(-time.Second)
	if p.icmpFiltered("1.2.3.4") {
		t.Error("an expired memo must be forgotten")
	}
}

func TestResolveTargetAcceptsLiterals(t *testing.T) {
	ip, err := resolveTarget(context.Background(), "192.0.2.5")
	if err != nil || ip.String() != "192.0.2.5" {
		t.Errorf("literal resolution failed: %v %v", ip, err)
	}
	if _, err := resolveTarget(context.Background(), "invalid..name"); err == nil {
		t.Error("expected an error for an invalid name")
	}
}
