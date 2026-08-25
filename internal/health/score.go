// Package health computes the iPulse Internet Health Score.
//
// The score is a documented, deterministic weighted average of component scores. It is
// not a model, it is not learned, and it is not hidden: every component is a linear
// interpolation between a "good" and a "bad" threshold from the configuration, and the
// computation publishes both the component scores and the weights that produced the
// total, so any number it reports can be reproduced by hand.
package health

import (
	"sort"

	"github.com/ipulse/ipulse/internal/util"
)

// Component names. These appear in the API and the dashboard.
const (
	ComponentAvailability = "availability"
	ComponentDownload     = "download"
	ComponentUpload       = "upload"
	ComponentLatency      = "latency"
	ComponentJitter       = "jitter"
	ComponentPacketLoss   = "packet_loss"
	ComponentDNS          = "dns"
)

// Weights are the relative contributions of each component.
type Weights struct {
	Availability float64
	Download     float64
	Upload       float64
	Latency      float64
	Jitter       float64
	PacketLoss   float64
	DNS          float64
}

// Thresholds define the good and bad ends of each component's scale.
type Thresholds struct {
	LatencyGoodMS float64
	LatencyBadMS  float64
	JitterGoodMS  float64
	JitterBadMS   float64
	LossGoodPct   float64
	LossBadPct    float64
	DNSGoodMS     float64
	DNSBadMS      float64
}

// Inputs are the measurements the score is computed from. A component with no
// measurement is excluded rather than assumed: scoring an unmeasured component as zero
// would report a broken connection on a host that simply has not finished its first
// speed test.
type Inputs struct {
	AvailabilityPct  float64
	HaveAvailability bool

	DownloadMbps     float64
	ExpectedDownload float64
	HaveDownload     bool

	UploadMbps     float64
	ExpectedUpload float64
	HaveUpload     bool

	LatencyMS   float64
	HaveLatency bool

	JitterMS   float64
	HaveJitter bool

	LossPct  float64
	HaveLoss bool

	DNSMS   float64
	HaveDNS bool
}

// Score is the computed result.
type Score struct {
	// Total is the weighted average, 0-100.
	Total float64 `json:"total"`
	// Components holds each component's 0-100 score.
	Components map[string]float64 `json:"components"`
	// Weights holds the effective weight of each component after excluding the ones
	// with no data, so the total can be verified.
	Weights map[string]float64 `json:"weights"`
	// Worst names the lowest-scoring component, which is the one to look at first.
	Worst string `json:"worst_component"`
	// WorstScore is that component's score.
	WorstScore float64 `json:"worst_score"`
	// Missing lists components with no data.
	Missing []string `json:"missing,omitempty"`
	// Formula documents the computation.
	Formula string `json:"formula"`
}

// Formula is the published scoring formula.
const Formula = "score = sum(weight_i * component_i) / sum(weight_i), " +
	"each component linearly scaled 0-100 between its configured good and bad thresholds; " +
	"components with no measurement are excluded and their weight is redistributed"

// Compute produces the score.
//
// Throughput is scored against the operator's advertised plan, because that is the only
// absolute reference available: without a configured plan there is no meaningful way to
// say whether 40 Mbps is good, so the throughput components are simply excluded.
func Compute(in Inputs, w Weights, th Thresholds) Score {
	s := Score{
		Components: map[string]float64{},
		Weights:    map[string]float64{},
		Formula:    Formula,
	}

	type entry struct {
		name   string
		weight float64
		score  float64
		have   bool
	}
	entries := []entry{
		{ComponentAvailability, w.Availability, util.Clamp(in.AvailabilityPct, 0, 100), in.HaveAvailability},
		{ComponentLatency, w.Latency, util.LinearScore(in.LatencyMS, th.LatencyGoodMS, th.LatencyBadMS), in.HaveLatency},
		{ComponentJitter, w.Jitter, util.LinearScore(in.JitterMS, th.JitterGoodMS, th.JitterBadMS), in.HaveJitter},
		{ComponentPacketLoss, w.PacketLoss, util.LinearScore(in.LossPct, th.LossGoodPct, th.LossBadPct), in.HaveLoss},
		{ComponentDNS, w.DNS, util.LinearScore(in.DNSMS, th.DNSGoodMS, th.DNSBadMS), in.HaveDNS},
	}

	// Throughput: 100 at or above the plan, 0 at a tenth of it. A tenth is the point at
	// which a connection is unusable for what it was sold as.
	if in.HaveDownload && in.ExpectedDownload > 0 {
		entries = append(entries, entry{ComponentDownload, w.Download,
			util.LinearScore(in.DownloadMbps, in.ExpectedDownload, in.ExpectedDownload*0.1), true})
	} else {
		entries = append(entries, entry{ComponentDownload, w.Download, 0, false})
	}
	if in.HaveUpload && in.ExpectedUpload > 0 {
		entries = append(entries, entry{ComponentUpload, w.Upload,
			util.LinearScore(in.UploadMbps, in.ExpectedUpload, in.ExpectedUpload*0.1), true})
	} else {
		entries = append(entries, entry{ComponentUpload, w.Upload, 0, false})
	}

	var weighted, totalWeight float64
	s.WorstScore = 101
	for _, e := range entries {
		if !e.have || e.weight <= 0 {
			if !e.have {
				s.Missing = append(s.Missing, e.name)
			}
			continue
		}
		score := util.Clamp(e.score, 0, 100)
		s.Components[e.name] = round1(score)
		s.Weights[e.name] = e.weight
		weighted += e.weight * score
		totalWeight += e.weight
		if score < s.WorstScore {
			s.WorstScore, s.Worst = round1(score), e.name
		}
	}
	sort.Strings(s.Missing)

	if totalWeight <= 0 {
		// Nothing measurable yet: report no score rather than a misleading zero.
		s.Total = 0
		s.Worst = ""
		s.WorstScore = 0
		return s
	}
	s.Total = round1(weighted / totalWeight)
	if s.WorstScore > 100 {
		s.WorstScore = 0
	}
	return s
}

// Usable reports whether enough components had data for the score to mean anything.
func (s Score) Usable() bool { return len(s.Components) > 0 }

// Grade renders a human label for the score, used by the dashboard.
func (s Score) Grade() string {
	switch {
	case !s.Usable():
		return "unknown"
	case s.Total >= 90:
		return "excellent"
	case s.Total >= 75:
		return "good"
	case s.Total >= 60:
		return "fair"
	case s.Total >= 40:
		return "poor"
	default:
		return "bad"
	}
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
