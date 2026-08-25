package traffic

import (
	"math"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/platform"
)

func iface(name, typ string, rx, tx uint64) platform.Interface {
	return platform.Interface{
		Name: name, Type: typ, Up: true, Running: true,
		Counters: platform.Counters{RxBytes: rx, TxBytes: tx},
	}
}

// TestFirstSampleEstablishesBaseline matters because a rate needs two readings; emitting
// one after a single reading would report the interface's lifetime total as a rate.
func TestFirstSampleEstablishesBaseline(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	if out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 1<<30, 1<<28)}, now); len(out) != 0 {
		t.Errorf("first sample produced %d results, want 0", len(out))
	}
	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 1<<30, 1<<28)}, now.Add(time.Second))
	if len(out) != 1 {
		t.Fatalf("second sample produced %d results", len(out))
	}
	if out[0].RxBps != 0 || out[0].TxBps != 0 {
		t.Errorf("unchanged counters should give a zero rate, got %+v", out[0])
	}
}

func TestRateCalculation(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 0, 0)}, now)

	// 12.5 MB received in 1 second is 100 Mbps.
	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 12_500_000, 1_250_000)}, now.Add(time.Second))
	if len(out) != 1 {
		t.Fatalf("got %d samples", len(out))
	}
	got := out[0]
	if math.Abs(got.RxBps-100e6) > 1 {
		t.Errorf("rx = %v bps, want 100 Mbps", got.RxBps)
	}
	if math.Abs(got.TxBps-10e6) > 1 {
		t.Errorf("tx = %v bps, want 10 Mbps", got.TxBps)
	}
	if got.RxDelta != 12_500_000 {
		t.Errorf("rx delta = %d", got.RxDelta)
	}
	if !got.Usable() {
		t.Error("sample should be usable")
	}
}

// TestIntervalIsMeasuredPerInterface guards against a skipped cycle inflating the rate.
func TestIntervalIsMeasuredPerInterface(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 0, 0)}, now)

	// Ten seconds later, 125 MB: still 100 Mbps, not 1 Gbps.
	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 125_000_000, 0)}, now.Add(10*time.Second))
	if math.Abs(out[0].RxBps-100e6) > 1 {
		t.Errorf("rx = %v bps, want 100 Mbps over a 10s interval", out[0].RxBps)
	}
	if out[0].Interval != 10*time.Second {
		t.Errorf("interval = %v", out[0].Interval)
	}
}

// TestCounterResetIsDetected is the property that stops a driver reload from being
// reported as a terabit spike.
func TestCounterResetIsDetected(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 1<<40, 1<<38)}, now)

	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 1000, 500)}, now.Add(time.Second))
	if len(out) != 1 {
		t.Fatalf("got %d samples", len(out))
	}
	if !out[0].Reset {
		t.Error("a counter going backwards must be reported as a reset")
	}
	if out[0].Usable() {
		t.Error("a reset sample must not be usable for rate analysis")
	}
	if out[0].RxBps != 0 {
		t.Errorf("a reset must not produce a rate, got %v", out[0].RxBps)
	}

	// The next sample recovers normally from the new baseline.
	out = s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 12_501_000, 500)}, now.Add(2*time.Second))
	if !out[0].Usable() || math.Abs(out[0].RxBps-100e6) > 1e6 {
		t.Errorf("recovery sample wrong: %+v", out[0])
	}
}

// TestSelfTrafficIsExcluded is the property that stops iPulse's own speed test from
// looking like a bandwidth spike.
func TestSelfTrafficIsExcluded(t *testing.T) {
	self := NewSelfTraffic(time.Hour)
	s := NewSampler(Config{ExcludeSelf: true}, self)
	now := time.Now()
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 0, 0)}, now)

	// 100 MB crossed the interface in one second, of which iPulse itself moved 99 MB.
	self.Record(now, now.Add(time.Second), 99_000_000, 0, "speedtest")
	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 100_000_000, 0)}, now.Add(time.Second))

	got := out[0]
	// The remaining 1 MB/s is 8 Mbps.
	if math.Abs(got.RxBps-8e6) > 1e5 {
		t.Errorf("rx after exclusion = %v bps, want about 8 Mbps", got.RxBps)
	}
	if !got.SelfActive {
		t.Error("the sample must be marked as overlapping iPulse's own transfer")
	}
	if got.SelfRxBps < 700e6 {
		t.Errorf("self rate = %v bps, want about 792 Mbps", got.SelfRxBps)
	}
}

// TestSelfTrafficNeverProducesNegativeRates guards the subtraction: attribution is
// proportional, so a small overshoot must clamp to zero rather than go negative.
func TestSelfTrafficNeverProducesNegativeRates(t *testing.T) {
	self := NewSelfTraffic(time.Hour)
	s := NewSampler(Config{ExcludeSelf: true}, self)
	now := time.Now()
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 0, 0)}, now)

	self.Record(now, now.Add(time.Second), 200_000_000, 200_000_000, "speedtest")
	out := s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 100_000_000, 100_000_000)}, now.Add(time.Second))
	if out[0].RxBps < 0 || out[0].TxBps < 0 {
		t.Errorf("negative rate after exclusion: %+v", out[0])
	}
}

func TestInterfaceFiltering(t *testing.T) {
	s := NewSampler(Config{Exclude: []string{"docker*", "veth*", "lo"}}, nil)
	now := time.Now()
	ifaces := []platform.Interface{
		iface("eth0", platform.IfaceEthernet, 0, 0),
		iface("docker0", platform.IfaceVirtual, 0, 0),
		iface("veth1a2b", platform.IfaceVirtual, 0, 0),
		iface("lo", platform.IfaceLoopback, 0, 0),
		iface("wlan0", platform.IfaceWireless, 0, 0),
	}
	s.Sample(ifaces, now)
	if s.Tracked() != 2 {
		t.Errorf("tracking %d interfaces, want 2 (eth0 and wlan0)", s.Tracked())
	}

	// An include list overrides the exclude list.
	only := NewSampler(Config{Include: []string{"wlan0"}}, nil)
	only.Sample(ifaces, now)
	if only.Tracked() != 1 {
		t.Errorf("include list tracked %d interfaces, want 1", only.Tracked())
	}
}

func TestLoopbackIsNeverSampled(t *testing.T) {
	s := NewSampler(Config{}, nil)
	s.Sample([]platform.Interface{iface("lo", platform.IfaceLoopback, 0, 0)}, time.Now())
	if s.Tracked() != 0 {
		t.Error("loopback must never be sampled: it carries no Internet traffic")
	}
}

func TestDisappearedInterfacesAreForgotten(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	s.Sample([]platform.Interface{
		iface("eth0", platform.IfaceEthernet, 0, 0),
		iface("veth0", platform.IfaceOther, 0, 0),
	}, now)
	if s.Tracked() != 2 {
		t.Fatalf("tracking %d", s.Tracked())
	}
	s.Sample([]platform.Interface{iface("eth0", platform.IfaceEthernet, 0, 0)}, now.Add(time.Second))
	if s.Tracked() != 1 {
		t.Errorf("tracking %d after an interface disappeared, want 1", s.Tracked())
	}
}

func TestPrimaryAndBusiest(t *testing.T) {
	samples := []Sample{
		{Interface: "eth0", RxBps: 1e6, TxBps: 1e6, Interval: time.Second},
		{Interface: "wlan0", RxBps: 50e6, TxBps: 5e6, Interval: time.Second},
		{Interface: "tun0", Reset: true, Interval: time.Second},
	}
	if s, ok := Primary(samples, "wlan0"); !ok || s.RxBps != 50e6 {
		t.Errorf("Primary = %+v ok=%v", s, ok)
	}
	if _, ok := Primary(samples, "missing"); ok {
		t.Error("Primary should report a missing interface")
	}
	b, ok := Busiest(samples)
	if !ok || b.Interface != "wlan0" {
		t.Errorf("Busiest = %+v ok=%v", b, ok)
	}
}

func TestErrorAndDropDeltas(t *testing.T) {
	s := NewSampler(Config{}, nil)
	now := time.Now()
	before := iface("eth0", platform.IfaceEthernet, 0, 0)
	s.Sample([]platform.Interface{before}, now)

	after := before
	after.Counters.RxErrors = 30
	after.Counters.TxDropped = 12
	out := s.Sample([]platform.Interface{after}, now.Add(2*time.Second))
	if out[0].ErrorsDelta != 30 || out[0].DroppedDelta != 12 {
		t.Errorf("deltas = errors %d dropped %d", out[0].ErrorsDelta, out[0].DroppedDelta)
	}
}
