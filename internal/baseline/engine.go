// Package baseline maintains time-aware adaptive baselines for every monitored metric.
//
// Two ideas make the baselines useful rather than merely present. First, they are
// time-aware: traffic at 2 PM on a weekday is compared with other weekday afternoons,
// not with 3 AM on a Sunday, because comparing them is what produces nonsense alerts.
// Second, a baseline is inert until it has enough observations, so nothing is ever
// declared anomalous against a history of three samples.
package baseline

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/util"
)

// Key identifies one baseline: a metric, an optional dimension (interface, target,
// process) and a time bucket.
type Key struct {
	Metric    string
	Dimension string
	Bucket    string
}

// String renders the key for logs and events.
func (k Key) String() string {
	if k.Dimension == "" {
		return k.Metric + "@" + k.Bucket
	}
	return k.Metric + "[" + k.Dimension + "]@" + k.Bucket
}

// Baseline is the accumulated history for one key.
type Baseline struct {
	Key
	// Samples is the number of observations folded in.
	Samples int64
	// Mean and M2 are Welford accumulators, so the mean and variance are exact without
	// retaining samples.
	Mean float64
	M2   float64
	Min  float64
	Max  float64
	// EWMA weights recent observations more heavily, which is what lets a baseline
	// follow a genuine change in conditions instead of resisting it forever.
	EWMA float64
	// Median, MAD and the percentiles are computed from the recent-sample window.
	Median float64
	MAD    float64
	P10    float64
	P25    float64
	P75    float64
	P90    float64
	P95    float64
	P99    float64
	// Established reports whether the minimum observation count has been reached.
	Established bool
	FirstSeen   time.Time
	UpdatedAt   time.Time

	// window holds the most recent samples, used for the robust statistics. It is a
	// sliding window rather than a random reservoir so the percentiles describe recent
	// behaviour, which is what a detector should compare against.
	window []float64
}

// StdDev returns the sample standard deviation.
func (b Baseline) StdDev() float64 {
	if b.Samples < 2 {
		return 0
	}
	return math.Sqrt(b.M2 / float64(b.Samples-1))
}

// Usable reports whether the baseline may be used for detection.
func (b Baseline) Usable() bool { return b.Established && b.Samples > 0 }

// Config configures the engine.
type Config struct {
	// MinObservations is how many samples a bucket needs before detectors may use it.
	MinObservations int
	// TimeBuckets enables hour-of-day and weekday/weekend aware buckets.
	TimeBuckets bool
	// BucketHours is the width of an hour bucket.
	BucketHours int
	// EWMAAlpha weights recent samples in the exponentially-weighted average.
	EWMAAlpha float64
	// WindowSize bounds the recent-sample window used for percentiles.
	WindowSize int
	// MaxAge drops buckets untouched for this long.
	MaxAge time.Duration
}

// Engine holds the baselines for every metric and bucket.
type Engine struct {
	cfg Config

	mu        sync.RWMutex
	baselines map[Key]*Baseline
	dirty     map[Key]bool
	// newlyEstablished collects buckets that just became usable, so the agent can
	// report it once per bucket.
	newlyEstablished []Baseline
}

// New creates an engine, applying defaults for unset values.
func New(cfg Config) *Engine {
	if cfg.MinObservations <= 0 {
		cfg.MinObservations = 30
	}
	if cfg.BucketHours <= 0 || 24%cfg.BucketHours != 0 {
		cfg.BucketHours = 1
	}
	if cfg.EWMAAlpha <= 0 || cfg.EWMAAlpha > 1 {
		cfg.EWMAAlpha = 0.1
	}
	if cfg.WindowSize < 16 {
		cfg.WindowSize = 256
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 30 * 24 * time.Hour
	}
	return &Engine{
		cfg:       cfg,
		baselines: map[Key]*Baseline{},
		dirty:     map[Key]bool{},
	}
}

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// BucketFor returns the time-bucket label for an instant.
//
// The label separates weekdays from weekends and groups hours, which captures the two
// patterns that actually drive network behaviour: the working day and the working week.
// A finer model would need far more history before any bucket became usable.
func (e *Engine) BucketFor(t time.Time) string {
	if !e.cfg.TimeBuckets {
		return "all"
	}
	dayClass := "wd"
	switch t.Weekday() {
	case time.Saturday, time.Sunday:
		dayClass = "we"
	}
	hour := (t.Hour() / e.cfg.BucketHours) * e.cfg.BucketHours
	return fmt.Sprintf("%s-%02d", dayClass, hour)
}

// Observe folds a sample into its bucket and returns the baseline as it was *before*
// this sample was added.
//
// Returning the prior state is essential: a detector must compare an observation against
// history, not against a baseline that already contains the observation. Comparing a
// value with a baseline it just moved is how detectors end up unable to see anything.
func (e *Engine) Observe(metric, dimension string, value float64, at time.Time) (before Baseline, established bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return Baseline{}, false
	}
	key := Key{Metric: metric, Dimension: dimension, Bucket: e.BucketFor(at)}

	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.baselines[key]
	if !ok {
		b = &Baseline{Key: key, FirstSeen: at, Min: value, Max: value}
		e.baselines[key] = b
	}
	prior := *b
	prior.window = nil // the caller does not need the raw window

	wasEstablished := b.Established
	e.add(b, value, at)
	e.dirty[key] = true

	if !wasEstablished && b.Established {
		snapshot := *b
		snapshot.window = nil
		e.newlyEstablished = append(e.newlyEstablished, snapshot)
		established = true
	}
	return prior, established
}

// add folds one value into a baseline.
func (e *Engine) add(b *Baseline, value float64, at time.Time) {
	b.Samples++
	// Welford's method: numerically stable, and needs no stored samples.
	delta := value - b.Mean
	b.Mean += delta / float64(b.Samples)
	b.M2 += delta * (value - b.Mean)

	if b.Samples == 1 || value < b.Min {
		b.Min = value
	}
	if b.Samples == 1 || value > b.Max {
		b.Max = value
	}
	if b.Samples == 1 {
		b.EWMA = value
	} else {
		b.EWMA = util.EWMA(b.EWMA, value, e.cfg.EWMAAlpha)
	}

	b.window = append(b.window, value)
	if len(b.window) > e.cfg.WindowSize {
		b.window = b.window[len(b.window)-e.cfg.WindowSize:]
	}
	e.recompute(b)

	b.UpdatedAt = at
	if b.FirstSeen.IsZero() {
		b.FirstSeen = at
	}
	b.Established = b.Samples >= int64(e.cfg.MinObservations)
}

// recompute refreshes the robust statistics from the recent window.
func (e *Engine) recompute(b *Baseline) {
	if len(b.window) == 0 {
		return
	}
	stats := util.Describe(b.window)
	b.Median = stats.Median
	b.MAD = stats.MAD
	b.P10, b.P25, b.P75 = stats.P10, stats.P25, stats.P75
	b.P90, b.P95, b.P99 = stats.P90, stats.P95, stats.P99
}

// Get returns the baseline for a metric and dimension at a time.
func (e *Engine) Get(metric, dimension string, at time.Time) (Baseline, bool) {
	key := Key{Metric: metric, Dimension: dimension, Bucket: e.BucketFor(at)}
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, ok := e.baselines[key]
	if !ok {
		return Baseline{}, false
	}
	out := *b
	out.window = nil
	return out, true
}

// GetAggregate returns a baseline combining every bucket for a metric, which is what a
// detector should use when the time-bucketed baseline is not yet established. It is
// coarser, but a coarse baseline with real history beats no baseline at all.
func (e *Engine) GetAggregate(metric, dimension string) (Baseline, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	agg := Baseline{Key: Key{Metric: metric, Dimension: dimension, Bucket: "aggregate"}}
	var all []float64
	for key, b := range e.baselines {
		if key.Metric != metric || key.Dimension != dimension {
			continue
		}
		if agg.Samples == 0 {
			agg.Min, agg.Max, agg.FirstSeen = b.Min, b.Max, b.FirstSeen
		}
		// Pooled mean, weighted by sample count.
		total := agg.Samples + b.Samples
		if total > 0 {
			agg.Mean = (agg.Mean*float64(agg.Samples) + b.Mean*float64(b.Samples)) / float64(total)
		}
		agg.Samples = total
		agg.M2 += b.M2
		if b.Min < agg.Min {
			agg.Min = b.Min
		}
		if b.Max > agg.Max {
			agg.Max = b.Max
		}
		if b.UpdatedAt.After(agg.UpdatedAt) {
			agg.UpdatedAt = b.UpdatedAt
		}
		if !b.FirstSeen.IsZero() && (agg.FirstSeen.IsZero() || b.FirstSeen.Before(agg.FirstSeen)) {
			agg.FirstSeen = b.FirstSeen
		}
		all = append(all, b.window...)
		if agg.EWMA == 0 {
			agg.EWMA = b.EWMA
		}
	}
	if agg.Samples == 0 {
		return Baseline{}, false
	}
	if len(all) > 0 {
		stats := util.Describe(all)
		agg.Median, agg.MAD = stats.Median, stats.MAD
		agg.P10, agg.P25, agg.P75 = stats.P10, stats.P25, stats.P75
		agg.P90, agg.P95, agg.P99 = stats.P90, stats.P95, stats.P99
	}
	agg.Established = agg.Samples >= int64(e.cfg.MinObservations)
	return agg, true
}

// Best returns the time-bucketed baseline when it is established, and otherwise the
// aggregate across buckets. Detectors use this so they work from the first hours of
// operation without waiting for every bucket to fill.
func (e *Engine) Best(metric, dimension string, at time.Time) (Baseline, bool) {
	if b, ok := e.Get(metric, dimension, at); ok && b.Usable() {
		return b, true
	}
	agg, ok := e.GetAggregate(metric, dimension)
	if ok && agg.Usable() {
		return agg, true
	}
	return Baseline{}, false
}

// TakeNewlyEstablished returns and clears the buckets that just became usable.
func (e *Engine) TakeNewlyEstablished() []Baseline {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.newlyEstablished
	e.newlyEstablished = nil
	return out
}

// Row is the persisted form of a baseline.
type Row struct {
	Metric      string
	Dimension   string
	Bucket      string
	Samples     int64
	Mean        float64
	M2          float64
	Min         float64
	Max         float64
	EWMA        float64
	Median      float64
	MAD         float64
	P10         float64
	P25         float64
	P75         float64
	P90         float64
	P95         float64
	P99         float64
	Window      string
	Established bool
	FirstSeen   time.Time
	UpdatedAt   time.Time
}

// TakeDirty returns the baselines changed since the last call, for persistence.
func (e *Engine) TakeDirty() []Row {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]Row, 0, len(e.dirty))
	for key := range e.dirty {
		b, ok := e.baselines[key]
		if !ok {
			continue
		}
		row := Row{
			Metric: b.Metric, Dimension: b.Dimension, Bucket: b.Bucket,
			Samples: b.Samples, Mean: b.Mean, M2: b.M2, Min: b.Min, Max: b.Max, EWMA: b.EWMA,
			Median: b.Median, MAD: b.MAD, P10: b.P10, P25: b.P25, P75: b.P75,
			P90: b.P90, P95: b.P95, P99: b.P99,
			Established: b.Established, FirstSeen: b.FirstSeen, UpdatedAt: b.UpdatedAt,
		}
		if len(b.window) > 0 {
			if data, err := json.Marshal(b.window); err == nil {
				row.Window = string(data)
			}
		}
		out = append(out, row)
	}
	e.dirty = map[Key]bool{}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Metric != out[j].Metric {
			return out[i].Metric < out[j].Metric
		}
		return out[i].Bucket < out[j].Bucket
	})
	return out
}

// Load restores persisted baselines, so a restart does not discard learned history.
func (e *Engine) Load(rows []Row) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range rows {
		key := Key{Metric: r.Metric, Dimension: r.Dimension, Bucket: r.Bucket}
		b := &Baseline{
			Key: key, Samples: r.Samples, Mean: r.Mean, M2: r.M2, Min: r.Min, Max: r.Max,
			EWMA: r.EWMA, Median: r.Median, MAD: r.MAD, P10: r.P10, P25: r.P25, P75: r.P75,
			P90: r.P90, P95: r.P95, P99: r.P99,
			Established: r.Established, FirstSeen: r.FirstSeen, UpdatedAt: r.UpdatedAt,
		}
		if r.Window != "" {
			var window []float64
			if err := json.Unmarshal([]byte(r.Window), &window); err == nil {
				if len(window) > e.cfg.WindowSize {
					window = window[len(window)-e.cfg.WindowSize:]
				}
				b.window = window
			}
		}
		// Re-derive rather than trust the stored flag, so a configuration change to
		// min_observations takes effect on restart.
		b.Established = b.Samples >= int64(e.cfg.MinObservations)
		e.baselines[key] = b
	}
}

// Prune drops buckets untouched for longer than MaxAge, so a machine that changes
// networks does not carry stale baselines forever.
func (e *Engine) Prune(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-e.cfg.MaxAge)
	removed := 0
	for key, b := range e.baselines {
		if b.UpdatedAt.Before(cutoff) {
			delete(e.baselines, key)
			delete(e.dirty, key)
			removed++
		}
	}
	return removed
}

// Count returns how many baselines are held, and how many are established.
func (e *Engine) Count() (total, established int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, b := range e.baselines {
		total++
		if b.Established {
			established++
		}
	}
	return total, established
}

// Metrics lists the metrics with at least one baseline.
func (e *Engine) Metrics() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	seen := map[string]bool{}
	for key := range e.baselines {
		seen[key.Metric] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
