package anomaly

import (
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/baseline"
	"github.com/ipulse/ipulse/internal/util"
)

// Direction says which way a metric is bad.
type Direction int

// Directions.
const (
	// Above means larger is worse: latency, jitter, loss, DNS time.
	Above Direction = iota
	// Below means smaller is worse: throughput.
	Below
)

// Finding is one detector's conclusion about a sample.
type Finding struct {
	Metric    string
	Dimension string
	// Value is the observed sample.
	Value float64
	// Baseline is the reference the sample was compared against.
	Baseline float64
	// DeviationPct is the signed deviation from the baseline, as a percentage.
	DeviationPct float64
	// ZScore is set for the robust-deviation rules.
	ZScore float64
	// Bucket names the time bucket the baseline came from, so a reader can tell
	// whether the comparison was time-aware.
	Bucket string
	// Observations is how many samples the baseline is built from, which is the honest
	// measure of how much the finding is worth.
	Observations int64
	Consecutive  int
	Duration     time.Duration
	// Recovered marks the end of a previously reported condition.
	Recovered bool
}

// DeviationRule reports when a metric deviates from its baseline by more than a
// configured percentage.
//
// Two guards keep it from being noisy. A minimum absolute value stops a 5 ms baseline
// rising to 12 ms from being reported as a 140 % degradation, and the shared gate
// requires the condition to persist before anything is emitted.
type DeviationRule struct {
	Metric    string
	Direction Direction
	// ThresholdPercent is the deviation from baseline that counts as a breach.
	ThresholdPercent float64
	// MinAbsolute suppresses findings while the absolute value is still acceptable
	// (for Above rules) or already high (for Below rules).
	MinAbsolute float64
	// UseMedian compares against the median rather than the mean, which is the right
	// choice for metrics with occasional large outliers.
	UseMedian bool
	gate      *Gate
}

// NewDeviationRule creates a rule sharing the supplied gate.
func NewDeviationRule(metric string, dir Direction, thresholdPercent, minAbsolute float64, useMedian bool, gate *Gate) *DeviationRule {
	return &DeviationRule{
		Metric: metric, Direction: dir, ThresholdPercent: thresholdPercent,
		MinAbsolute: minAbsolute, UseMedian: useMedian, gate: gate,
	}
}

// reference returns the baseline value this rule compares against.
func (r *DeviationRule) reference(b baseline.Baseline) float64 {
	if r.UseMedian && b.Median > 0 {
		return b.Median
	}
	if b.Mean != 0 {
		return b.Mean
	}
	return b.Median
}

// Evaluate compares one sample with its baseline.
func (r *DeviationRule) Evaluate(b baseline.Baseline, value float64, dimension string, now time.Time) (Finding, bool) {
	if !b.Usable() || r.ThresholdPercent <= 0 {
		return Finding{}, false
	}
	ref := r.reference(b)
	if ref <= 0 {
		return Finding{}, false
	}
	deviation := util.PercentDeviation(value, ref)

	breached := false
	switch r.Direction {
	case Above:
		// Larger is worse, and only once the absolute value matters.
		breached = deviation >= r.ThresholdPercent && value >= r.MinAbsolute
	case Below:
		// Smaller is worse. MinAbsolute here means "do not report a slow link getting
		// slower": below this rate the relative movement is noise.
		breached = -deviation >= r.ThresholdPercent && ref >= r.MinAbsolute
	}

	key := r.Metric + "|" + dimension
	d := r.gate.Observe(key, breached, now)
	if !d.Fire && !d.Recovered {
		return Finding{}, false
	}
	return Finding{
		Metric: r.Metric, Dimension: dimension, Value: value, Baseline: ref,
		DeviationPct: deviation, Bucket: b.Bucket, Observations: b.Samples,
		Consecutive: d.Consecutive, Duration: d.Duration, Recovered: d.Recovered,
	}, true
}

// ZScoreRule reports when a metric departs from its baseline by more than a number of
// robust standard deviations.
//
// A median/MAD z-score is used rather than mean/stddev because traffic rates are
// heavily skewed: a handful of large transfers would inflate a conventional standard
// deviation until nothing could ever exceed it.
type ZScoreRule struct {
	Metric string
	// Threshold is the z-score that counts as a breach.
	Threshold float64
	// MinAbsolute suppresses findings below an absolute value, so a statistically
	// enormous spike on an idle link is not reported as a bandwidth event.
	MinAbsolute float64
	// Direction limits the rule to increases (the usual case for traffic).
	Direction Direction
	gate      *Gate
}

// NewZScoreRule creates a robust-deviation rule.
func NewZScoreRule(metric string, threshold, minAbsolute float64, dir Direction, gate *Gate) *ZScoreRule {
	return &ZScoreRule{Metric: metric, Threshold: threshold, MinAbsolute: minAbsolute, Direction: dir, gate: gate}
}

// Evaluate compares one sample with its baseline.
func (r *ZScoreRule) Evaluate(b baseline.Baseline, value float64, dimension string, now time.Time) (Finding, bool) {
	if !b.Usable() || r.Threshold <= 0 {
		return Finding{}, false
	}
	median := b.Median
	if median == 0 {
		median = b.Mean
	}
	z := util.RobustZ(value, median, b.MAD)

	breached := false
	switch r.Direction {
	case Above:
		breached = z >= r.Threshold && value >= r.MinAbsolute
	case Below:
		breached = -z >= r.Threshold && median >= r.MinAbsolute
	}

	key := r.Metric + "|" + dimension
	d := r.gate.Observe(key, breached, now)
	if !d.Fire && !d.Recovered {
		return Finding{}, false
	}
	return Finding{
		Metric: r.Metric, Dimension: dimension, Value: value, Baseline: median,
		DeviationPct: util.PercentDeviation(value, median), ZScore: z,
		Bucket: b.Bucket, Observations: b.Samples,
		Consecutive: d.Consecutive, Duration: d.Duration, Recovered: d.Recovered,
	}, true
}

// SustainedRule reports a metric staying above a floor for a minimum duration. This is
// what separates "a large file was sent" from "something has been uploading for an hour",
// and it is the basis of the sustained-upload and sustained-bandwidth detectors.
type SustainedRule struct {
	Metric string
	// Floor is the value above which the condition is considered active.
	Floor float64
	// MinDuration is how long it must persist before being reported.
	MinDuration time.Duration
	// Repeat is how often an ongoing condition is re-reported. Zero reports it once.
	Repeat time.Duration

	mu    sync.Mutex
	state map[string]*sustainedState
}

type sustainedState struct {
	since    time.Time
	last     time.Time
	reported time.Time
	peak     float64
	total    float64
	samples  int
}

// NewSustainedRule creates a sustained-condition rule.
func NewSustainedRule(metric string, floor float64, minDuration, repeat time.Duration) *SustainedRule {
	return &SustainedRule{
		Metric: metric, Floor: floor, MinDuration: minDuration, Repeat: repeat,
		state: map[string]*sustainedState{},
	}
}

// SustainedFinding describes an ongoing or finished sustained condition.
type SustainedFinding struct {
	Metric    string
	Dimension string
	// Average and Peak describe the condition over its whole duration, not just the
	// sample that happened to trigger the report.
	Average  float64
	Peak     float64
	Duration time.Duration
	Samples  int
	// Ended marks the condition finishing rather than starting.
	Ended bool
}

// Observe folds one sample in and reports when the condition becomes, or stops being,
// sustained.
func (r *SustainedRule) Observe(dimension string, value float64, now time.Time) (SustainedFinding, bool) {
	if r.MinDuration <= 0 {
		return SustainedFinding{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.state[dimension]
	if !ok {
		st = &sustainedState{}
		r.state[dimension] = st
	}

	if value < r.Floor {
		if st.since.IsZero() {
			return SustainedFinding{}, false
		}
		// The condition has ended. Report the end only if the start was reported, so a
		// brief burst produces no events at all.
		duration := st.last.Sub(st.since)
		reported := !st.reported.IsZero()
		avg, peak, samples := st.average(), st.peak, st.samples
		*st = sustainedState{}
		if !reported {
			return SustainedFinding{}, false
		}
		return SustainedFinding{
			Metric: r.Metric, Dimension: dimension, Average: avg, Peak: peak,
			Duration: duration, Samples: samples, Ended: true,
		}, true
	}

	if st.since.IsZero() {
		st.since = now
	}
	st.last = now
	st.samples++
	st.total += value
	if value > st.peak {
		st.peak = value
	}

	elapsed := now.Sub(st.since)
	if elapsed < r.MinDuration {
		return SustainedFinding{}, false
	}
	if !st.reported.IsZero() {
		if r.Repeat <= 0 || now.Sub(st.reported) < r.Repeat {
			return SustainedFinding{}, false
		}
	}
	st.reported = now
	return SustainedFinding{
		Metric: r.Metric, Dimension: dimension, Average: st.average(), Peak: st.peak,
		Duration: elapsed, Samples: st.samples,
	}, true
}

func (s *sustainedState) average() float64 {
	if s.samples == 0 {
		return 0
	}
	return s.total / float64(s.samples)
}

// Active reports whether a dimension is currently above the floor.
func (r *SustainedRule) Active(dimension string) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state[dimension]
	if !ok || st.since.IsZero() {
		return 0, false
	}
	return st.last.Sub(st.since), true
}

// Reset forgets a dimension.
func (r *SustainedRule) Reset(dimension string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.state, dimension)
}

// QuietHours describes a period when activity is normally low.
type QuietHours struct {
	// Start and End are hours of the day, 0-23. Start may be greater than End to wrap
	// across midnight.
	Start int
	End   int
}

// Contains reports whether an instant falls inside the quiet period.
func (q QuietHours) Contains(t time.Time) bool {
	h := t.Hour()
	if q.Start == q.End {
		return false
	}
	if q.Start < q.End {
		return h >= q.Start && h < q.End
	}
	// Wraps midnight, for example 22:00 to 06:00.
	return h >= q.Start || h < q.End
}

// Describe renders the window for an event field.
func (q QuietHours) Describe() string {
	return pad2(q.Start) + ":00-" + pad2(q.End) + ":00"
}

func pad2(v int) string {
	if v < 10 {
		return "0" + string(rune('0'+v))
	}
	return string(rune('0'+v/10)) + string(rune('0'+v%10))
}
