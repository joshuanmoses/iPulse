package health

import (
	"math"
	"testing"
)

func defaultWeights() Weights {
	return Weights{Availability: 30, Download: 15, Upload: 10, Latency: 20, Jitter: 8, PacketLoss: 12, DNS: 5}
}

func defaultThresholds() Thresholds {
	return Thresholds{
		LatencyGoodMS: 20, LatencyBadMS: 200,
		JitterGoodMS: 3, JitterBadMS: 50,
		LossGoodPct: 0, LossBadPct: 5,
		DNSGoodMS: 20, DNSBadMS: 500,
	}
}

func perfectInputs() Inputs {
	return Inputs{
		AvailabilityPct: 100, HaveAvailability: true,
		DownloadMbps: 500, ExpectedDownload: 500, HaveDownload: true,
		UploadMbps: 50, ExpectedUpload: 50, HaveUpload: true,
		LatencyMS: 15, HaveLatency: true,
		JitterMS: 2, HaveJitter: true,
		LossPct: 0, HaveLoss: true,
		DNSMS: 12, HaveDNS: true,
	}
}

func TestPerfectConnectionScores100(t *testing.T) {
	s := Compute(perfectInputs(), defaultWeights(), defaultThresholds())
	if s.Total != 100 {
		t.Errorf("score = %v, want 100 (%v)", s.Total, s.Components)
	}
	if len(s.Components) != 7 {
		t.Errorf("expected all seven components, got %v", s.Components)
	}
	if s.Grade() != "excellent" {
		t.Errorf("grade = %q", s.Grade())
	}
}

func TestBrokenConnectionScores0(t *testing.T) {
	in := Inputs{
		AvailabilityPct: 0, HaveAvailability: true,
		DownloadMbps: 10, ExpectedDownload: 500, HaveDownload: true,
		UploadMbps: 1, ExpectedUpload: 50, HaveUpload: true,
		LatencyMS: 900, HaveLatency: true,
		JitterMS: 300, HaveJitter: true,
		LossPct: 40, HaveLoss: true,
		DNSMS: 3000, HaveDNS: true,
	}
	s := Compute(in, defaultWeights(), defaultThresholds())
	if s.Total != 0 {
		t.Errorf("score = %v, want 0 (%v)", s.Total, s.Components)
	}
	if s.Grade() != "bad" {
		t.Errorf("grade = %q", s.Grade())
	}
}

// TestScoreIsReproducibleByHand is the transparency property: the published formula must
// actually reproduce the number.
func TestScoreIsReproducibleByHand(t *testing.T) {
	in := perfectInputs()
	in.LatencyMS = 110 // exactly midway between 20 and 200 -> 50
	in.JitterMS = 26.5 // midway between 3 and 50 -> 50
	s := Compute(in, defaultWeights(), defaultThresholds())

	w := defaultWeights()
	expected := (w.Availability*100 + w.Download*100 + w.Upload*100 +
		w.Latency*50 + w.Jitter*50 + w.PacketLoss*100 + w.DNS*100) /
		(w.Availability + w.Download + w.Upload + w.Latency + w.Jitter + w.PacketLoss + w.DNS)
	if math.Abs(s.Total-round1(expected)) > 0.11 {
		t.Errorf("score = %v, hand calculation = %v (components %v)", s.Total, expected, s.Components)
	}
	if s.Worst != ComponentLatency && s.Worst != ComponentJitter {
		t.Errorf("worst component = %q, expected latency or jitter", s.Worst)
	}
}

// TestMissingComponentsAreExcluded is what stops a fresh install from reporting a
// terrible score before its first speed test.
func TestMissingComponentsAreExcluded(t *testing.T) {
	in := Inputs{
		AvailabilityPct: 100, HaveAvailability: true,
		LatencyMS: 15, HaveLatency: true,
		JitterMS: 2, HaveJitter: true,
		LossPct: 0, HaveLoss: true,
		DNSMS: 12, HaveDNS: true,
		// No throughput measurement yet.
	}
	s := Compute(in, defaultWeights(), defaultThresholds())
	if s.Total != 100 {
		t.Errorf("score = %v, want 100 with throughput excluded (%v)", s.Total, s.Components)
	}
	if _, ok := s.Components[ComponentDownload]; ok {
		t.Error("download must be excluded when there is no measurement")
	}
	if len(s.Missing) != 2 {
		t.Errorf("missing = %v, want download and upload", s.Missing)
	}
	// The weights that were used must be published.
	if s.Weights[ComponentAvailability] != 30 {
		t.Errorf("weights not reported: %v", s.Weights)
	}
}

// TestNoPlanExcludesThroughput documents the deliberate choice: without an advertised
// plan there is no absolute reference for "fast enough".
func TestNoPlanExcludesThroughput(t *testing.T) {
	in := perfectInputs()
	in.ExpectedDownload = 0
	in.ExpectedUpload = 0
	s := Compute(in, defaultWeights(), defaultThresholds())
	if _, ok := s.Components[ComponentDownload]; ok {
		t.Error("throughput must be excluded when no plan is configured")
	}
	if s.Total != 100 {
		t.Errorf("score = %v", s.Total)
	}
}

func TestNoDataYieldsUnusableScore(t *testing.T) {
	s := Compute(Inputs{}, defaultWeights(), defaultThresholds())
	if s.Usable() {
		t.Error("a score with no components must report itself unusable")
	}
	if s.Total != 0 || s.Worst != "" {
		t.Errorf("expected an empty score, got %+v", s)
	}
	if s.Grade() != "unknown" {
		t.Errorf("grade = %q", s.Grade())
	}
}

func TestOutageDominatesTheScore(t *testing.T) {
	in := perfectInputs()
	in.AvailabilityPct = 50 // half the window was down
	s := Compute(in, defaultWeights(), defaultThresholds())
	// Availability carries 30 of 100 weight, so halving it costs 15 points.
	if s.Total < 84 || s.Total > 86 {
		t.Errorf("score = %v, want about 85 (%v)", s.Total, s.Components)
	}
	if s.Worst != ComponentAvailability {
		t.Errorf("worst = %q, want availability", s.Worst)
	}
}

func TestZeroWeightComponentIsIgnored(t *testing.T) {
	w := defaultWeights()
	w.DNS = 0
	in := perfectInputs()
	in.DNSMS = 5000 // terrible, but weighted zero
	s := Compute(in, w, defaultThresholds())
	if s.Total != 100 {
		t.Errorf("score = %v, want 100 with DNS weighted out (%v)", s.Total, s.Components)
	}
	if _, ok := s.Components[ComponentDNS]; ok {
		t.Error("a zero-weight component must not appear in the breakdown")
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[float64]string{100: "excellent", 90: "excellent", 89.9: "good", 75: "good",
		74.9: "fair", 60: "fair", 59.9: "poor", 40: "poor", 39.9: "bad", 0: "bad"}
	for total, want := range cases {
		s := Score{Total: total, Components: map[string]float64{"x": total}}
		if got := s.Grade(); got != want {
			t.Errorf("Grade(%v) = %q, want %q", total, got, want)
		}
	}
}
