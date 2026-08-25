package util

import (
	"math"
	"net/netip"
	"testing"
)

func TestDescribe(t *testing.T) {
	s := Describe([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if s.Count != 10 || s.Min != 1 || s.Max != 10 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if math.Abs(s.Mean-5.5) > 1e-9 {
		t.Errorf("mean = %v, want 5.5", s.Mean)
	}
	if math.Abs(s.Median-5.5) > 1e-9 {
		t.Errorf("median = %v, want 5.5", s.Median)
	}
	if math.Abs(s.StdDev-3.0276503540974917) > 1e-9 {
		t.Errorf("stddev = %v", s.StdDev)
	}
	if math.Abs(s.P90-9.1) > 1e-9 {
		t.Errorf("p90 = %v, want 9.1", s.P90)
	}
}

func TestDescribeEdgeCases(t *testing.T) {
	if s := Describe(nil); s.Count != 0 {
		t.Errorf("empty input should give zero stats, got %+v", s)
	}
	s := Describe([]float64{42})
	if s.Count != 1 || s.Median != 42 || s.StdDev != 0 || s.P99 != 42 {
		t.Errorf("single sample: %+v", s)
	}
}

func TestDescribeDoesNotMutateInput(t *testing.T) {
	in := []float64{5, 1, 3}
	Describe(in)
	if in[0] != 5 || in[1] != 1 || in[2] != 3 {
		t.Errorf("input was reordered: %v", in)
	}
}

func TestRobustZ(t *testing.T) {
	// A steady 18 ms baseline jumping to 73 ms must score as a large deviation.
	if z := RobustZ(73, 18, 2); z < 10 {
		t.Errorf("expected a large z-score, got %v", z)
	}
	// Zero MAD must not produce NaN or a division by zero.
	if z := RobustZ(20, 18, 0); math.IsNaN(z) || math.IsInf(z, 0) {
		t.Errorf("zero MAD produced %v", z)
	}
	if z := RobustZ(0, 0, 0); z != 0 {
		t.Errorf("all-zero input should score 0, got %v", z)
	}
}

func TestPercentDeviation(t *testing.T) {
	if d := PercentDeviation(73, 18); math.Abs(d-305.5555555555556) > 1e-9 {
		t.Errorf("got %v", d)
	}
	if d := PercentDeviation(10, 0); d != 0 {
		t.Errorf("zero baseline should give 0, got %v", d)
	}
}

func TestLinearScoreBothDirections(t *testing.T) {
	// Lower is better (latency).
	if s := LinearScore(20, 20, 200); s != 100 {
		t.Errorf("latency at target should score 100, got %v", s)
	}
	if s := LinearScore(200, 20, 200); s != 0 {
		t.Errorf("latency at the bad end should score 0, got %v", s)
	}
	if s := LinearScore(110, 20, 200); math.Abs(s-50) > 1e-9 {
		t.Errorf("midpoint should score 50, got %v", s)
	}
	// Higher is better (throughput).
	if s := LinearScore(500, 500, 50); s != 100 {
		t.Errorf("throughput at plan should score 100, got %v", s)
	}
	if s := LinearScore(50, 500, 50); s != 0 {
		t.Errorf("throughput at the bad end should score 0, got %v", s)
	}
	if s := LinearScore(275, 500, 50); math.Abs(s-50) > 1e-9 {
		t.Errorf("throughput midpoint should score 50, got %v", s)
	}
}

func TestWelfordMatchesDescribe(t *testing.T) {
	vals := []float64{12, 19, 7, 25, 3, 44, 18, 21}
	var w Welford
	for _, v := range vals {
		w.Add(v)
	}
	s := Describe(vals)
	if math.Abs(w.Mean-s.Mean) > 1e-9 {
		t.Errorf("mean mismatch: %v vs %v", w.Mean, s.Mean)
	}
	if math.Abs(w.StdDev()-s.StdDev) > 1e-9 {
		t.Errorf("stddev mismatch: %v vs %v", w.StdDev(), s.StdDev)
	}
}

func TestPercentBelow(t *testing.T) {
	if p := PercentBelow([]float64{1, 2, 3, 4}, 3); p != 50 {
		t.Errorf("got %v, want 50", p)
	}
}

func TestIsPrivateAddr(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254",
		"192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
		"::1", "fd00::1", "fe80::1", "ff02::1", "224.0.0.1",
	}
	public := []string{
		"1.1.1.1", "8.8.8.8", "172.32.0.1", "172.15.255.255",
		"192.169.0.1", "203.0.113.5", "2606:4700:4700::1111",
	}
	for _, s := range private {
		if !IsPrivateAddr(mustAddr(t, s)) {
			t.Errorf("IsPrivateAddr(%s) = false, want true", s)
		}
	}
	for _, s := range public {
		if IsPrivateAddr(mustAddr(t, s)) {
			t.Errorf("IsPrivateAddr(%s) = true, want false", s)
		}
	}
}

func TestIsInternalWithExtraRanges(t *testing.T) {
	extra, invalid := ParsePrefixes([]string{"198.51.100.0/24", "203.0.113.7"})
	if len(invalid) != 0 {
		t.Fatalf("unexpected invalid prefixes: %v", invalid)
	}
	if !IsInternal(mustAddr(t, "198.51.100.9"), extra) {
		t.Error("an address inside a configured extra range must count as internal")
	}
	if !IsInternal(mustAddr(t, "203.0.113.7"), extra) {
		t.Error("a bare address in the extra list must count as internal")
	}
	if IsInternal(mustAddr(t, "203.0.113.8"), extra) {
		t.Error("a neighbouring address must not count as internal")
	}
}

func TestParsePrefixesReportsInvalid(t *testing.T) {
	out, invalid := ParsePrefixes([]string{"10.0.0.0/8", "not-a-prefix", "", "  192.168.0.0/16 "})
	if len(out) != 2 {
		t.Errorf("parsed %v", out)
	}
	if len(invalid) != 1 || invalid[0] != "not-a-prefix" {
		t.Errorf("invalid = %v", invalid)
	}
}

func TestIsDocumentationAddr(t *testing.T) {
	if !IsDocumentationAddr(mustAddr(t, "203.0.113.9")) {
		t.Error("203.0.113.0/24 is a documentation range")
	}
	if IsDocumentationAddr(mustAddr(t, "1.1.1.1")) {
		t.Error("1.1.1.1 is not a documentation address")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"lo", "lo", true},
		{"lo", "lo0", false},
		{"lo*", "lo", true},
		{"lo*", "loopback", true},
		{"docker*", "docker0", true},
		{"br-*", "br-1a2b3c", true},
		{"br-*", "bridge0", false},
		{"veth*", "veth9f1", true},
		{"*", "anything", true},
		{"Loopback*", "loopback pseudo-interface 1", true},
		{"*tun*", "wg-tunnel-0", true},
		{"eth0", "eth1", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pattern, c.s); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
	if !MatchesAnyGlob([]string{"lo", "docker*"}, "docker0") {
		t.Error("MatchesAnyGlob should match the second pattern")
	}
	if MatchesAnyGlob([]string{"lo", "docker*"}, "eth0") {
		t.Error("MatchesAnyGlob matched an unrelated name")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	return a
}
