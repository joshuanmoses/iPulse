// Package util holds small dependency-free helpers shared across iPulse: descriptive
// statistics, time bucketing and string helpers. Keeping the statistics in one place
// means the baseline engine, the API and the reporting code all compute percentiles
// the same way.
package util

import (
	"math"
	"sort"
)

// Stats is a descriptive summary of a sample set.
type Stats struct {
	Count  int     `json:"count"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	StdDev float64 `json:"stddev"`
	P10    float64 `json:"p10"`
	P25    float64 `json:"p25"`
	P75    float64 `json:"p75"`
	P90    float64 `json:"p90"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
	// MAD is the median absolute deviation, a robust dispersion measure used by the
	// anomaly detectors because network metrics are heavily skewed.
	MAD float64 `json:"mad"`
	Sum float64 `json:"sum"`
}

// Describe computes a full summary. The input is copied before sorting, so callers
// keep their ordering. An empty input yields a zero Stats.
func Describe(values []float64) Stats {
	if len(values) == 0 {
		return Stats{}
	}
	v := make([]float64, len(values))
	copy(v, values)
	sort.Float64s(v)

	s := Stats{
		Count: len(v),
		Min:   v[0],
		Max:   v[len(v)-1],
	}
	for _, x := range v {
		s.Sum += x
	}
	s.Mean = s.Sum / float64(len(v))
	if len(v) > 1 {
		var ss float64
		for _, x := range v {
			d := x - s.Mean
			ss += d * d
		}
		// Sample standard deviation (n-1): baselines are samples of a process, not
		// the whole population.
		s.StdDev = math.Sqrt(ss / float64(len(v)-1))
	}
	s.Median = percentileSorted(v, 50)
	s.P10 = percentileSorted(v, 10)
	s.P25 = percentileSorted(v, 25)
	s.P75 = percentileSorted(v, 75)
	s.P90 = percentileSorted(v, 90)
	s.P95 = percentileSorted(v, 95)
	s.P99 = percentileSorted(v, 99)
	s.MAD = madSorted(v, s.Median)
	return s
}

// Percentile returns the p-th percentile (0-100) using linear interpolation between
// the two closest ranks, which is the definition most operators expect.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	v := make([]float64, len(values))
	copy(v, values)
	sort.Float64s(v)
	return percentileSorted(v, p)
}

func percentileSorted(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := (p / 100) * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// Median returns the median of the values.
func Median(values []float64) float64 { return Percentile(values, 50) }

// Mean returns the arithmetic mean.
func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// MAD returns the median absolute deviation.
func MAD(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	v := make([]float64, len(values))
	copy(v, values)
	sort.Float64s(v)
	return madSorted(v, percentileSorted(v, 50))
}

func madSorted(sorted []float64, median float64) float64 {
	dev := make([]float64, len(sorted))
	for i, x := range sorted {
		dev[i] = math.Abs(x - median)
	}
	sort.Float64s(dev)
	return percentileSorted(dev, 50)
}

// MADScaleFactor converts a median absolute deviation into a standard-deviation
// equivalent for a normal distribution.
const MADScaleFactor = 1.4826

// RobustZ returns a median/MAD based z-score, which is far less sensitive to the
// outliers that dominate network traffic than a mean/stddev z-score.
//
// When the MAD is zero (a perfectly steady metric, common for an idle link) the
// function falls back to a relative-deviation score so a genuine jump is still
// detected instead of dividing by zero.
func RobustZ(value, median, mad float64) float64 {
	scaled := mad * MADScaleFactor
	if scaled > 1e-9 {
		return (value - median) / scaled
	}
	if math.Abs(median) > 1e-9 {
		return (value - median) / math.Abs(median)
	}
	if math.Abs(value) < 1e-9 {
		return 0
	}
	return math.Inf(1)
}

// PercentDeviation returns the signed deviation of value from baseline as a
// percentage. A zero baseline yields 0 to avoid a meaningless infinity.
func PercentDeviation(value, baseline float64) float64 {
	if math.Abs(baseline) < 1e-12 {
		return 0
	}
	return (value - baseline) / baseline * 100
}

// PercentBelow returns the percentage of values below a threshold.
func PercentBelow(values []float64, threshold float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var n int
	for _, v := range values {
		if v < threshold {
			n++
		}
	}
	return float64(n) / float64(len(values)) * 100
}

// Clamp constrains v to [lo, hi].
func Clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// LinearScore maps a value onto 0-100 where good scores 100 and bad scores 0.
// It supports both directions (good below bad, or good above bad) so it can score
// latency (lower is better) and throughput (higher is better) with one function.
func LinearScore(value, good, bad float64) float64 {
	if good == bad {
		if value <= good {
			return 100
		}
		return 0
	}
	if good < bad { // lower is better
		if value <= good {
			return 100
		}
		if value >= bad {
			return 0
		}
		return (bad - value) / (bad - good) * 100
	}
	// higher is better
	if value >= good {
		return 100
	}
	if value <= bad {
		return 0
	}
	return (value - bad) / (good - bad) * 100
}

// EWMA returns the next exponentially weighted moving average.
func EWMA(prev, sample, alpha float64) float64 {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1
	}
	return alpha*sample + (1-alpha)*prev
}

// Welford incrementally accumulates count, mean and M2 (sum of squared deviations)
// without storing samples, which is what makes the baseline engine cheap.
type Welford struct {
	Count int64
	Mean  float64
	M2    float64
}

// Add folds one sample into the accumulator.
func (w *Welford) Add(x float64) {
	w.Count++
	delta := x - w.Mean
	w.Mean += delta / float64(w.Count)
	w.M2 += delta * (x - w.Mean)
}

// Variance returns the sample variance.
func (w *Welford) Variance() float64 {
	if w.Count < 2 {
		return 0
	}
	return w.M2 / float64(w.Count-1)
}

// StdDev returns the sample standard deviation.
func (w *Welford) StdDev() float64 { return math.Sqrt(w.Variance()) }
