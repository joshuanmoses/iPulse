package traffic

import (
	"sync"
	"time"
)

// WindowAccumulator keeps a rolling total of transferred bytes over a fixed window.
//
// Rates answer "how fast right now"; volume answers "how much in the last few minutes",
// which is the question that matters for unexpected uploads. A large transfer can finish
// between two rate samples, so volume is accumulated from the deltas rather than derived
// from the instantaneous rate.
type WindowAccumulator struct {
	window time.Duration

	mu      sync.Mutex
	entries []windowEntry
}

type windowEntry struct {
	at     time.Time
	rx, tx int64
}

// NewWindowAccumulator creates an accumulator over the given window.
func NewWindowAccumulator(window time.Duration) *WindowAccumulator {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &WindowAccumulator{window: window}
}

// Add records the bytes transferred since the previous sample.
func (w *WindowAccumulator) Add(at time.Time, rx, tx int64) {
	if rx < 0 {
		rx = 0
	}
	if tx < 0 {
		tx = 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, windowEntry{at: at, rx: rx, tx: tx})
	w.trimLocked(at)
}

// Totals returns the bytes transferred within the window ending at now.
func (w *WindowAccumulator) Totals(now time.Time) (rx, tx int64, span time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.trimLocked(now)
	if len(w.entries) == 0 {
		return 0, 0, 0
	}
	for _, e := range w.entries {
		rx += e.rx
		tx += e.tx
	}
	return rx, tx, now.Sub(w.entries[0].at)
}

// Complete reports whether the accumulator holds a full window of data, so a detector
// can avoid comparing a partial window against a full-window baseline.
func (w *WindowAccumulator) Complete(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.entries) == 0 {
		return false
	}
	return now.Sub(w.entries[0].at) >= w.window*3/4
}

// Window returns the configured window length.
func (w *WindowAccumulator) Window() time.Duration { return w.window }

func (w *WindowAccumulator) trimLocked(now time.Time) {
	cutoff := now.Add(-w.window)
	first := 0
	for first < len(w.entries) && w.entries[first].at.Before(cutoff) {
		first++
	}
	if first > 0 {
		w.entries = append(w.entries[:0], w.entries[first:]...)
	}
}

// PeriodDetector finds a repeating period in a series of event times.
//
// Scheduled work - a backup, a sync, an update check - produces spikes at regular
// intervals. Recognising the regularity turns a stream of "bandwidth spike" events into
// one "this happens every 30 minutes" observation, which is context rather than an alert.
type PeriodDetector struct {
	mu    sync.Mutex
	times []time.Time
	max   int
}

// NewPeriodDetector creates a detector retaining the most recent occurrences.
func NewPeriodDetector(max int) *PeriodDetector {
	if max < 4 {
		max = 12
	}
	return &PeriodDetector{max: max}
}

// Record adds an occurrence.
func (p *PeriodDetector) Record(at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.times = append(p.times, at)
	if len(p.times) > p.max {
		p.times = p.times[len(p.times)-p.max:]
	}
}

// Period reports a dominant period when the intervals between occurrences are
// consistent. minOccurrences intervals are required, and the relative spread must be
// below tolerance, so genuinely irregular activity is not described as periodic.
func (p *PeriodDetector) Period(minOccurrences int, tolerance float64) (time.Duration, int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.times) < minOccurrences {
		return 0, len(p.times), false
	}

	intervals := make([]float64, 0, len(p.times)-1)
	for i := 1; i < len(p.times); i++ {
		d := p.times[i].Sub(p.times[i-1]).Seconds()
		if d <= 0 {
			continue
		}
		intervals = append(intervals, d)
	}
	if len(intervals) < minOccurrences-1 {
		return 0, len(p.times), false
	}

	var sum float64
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))
	if mean <= 0 {
		return 0, len(p.times), false
	}
	var variance float64
	for _, v := range intervals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(intervals))
	stddev := sqrt(variance)
	// The coefficient of variation is the scale-free measure of regularity: a 30 minute
	// period varying by a minute is regular, a 30 second period varying by a minute is not.
	if mean > 0 && stddev/mean > tolerance {
		return 0, len(p.times), false
	}
	return time.Duration(mean * float64(time.Second)), len(p.times), true
}

// Count returns how many occurrences are retained.
func (p *PeriodDetector) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.times)
}

// Reset forgets the recorded occurrences.
func (p *PeriodDetector) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.times = nil
}

// sqrt avoids importing math for one call in a hot-path-free file.
func sqrt(v float64) float64 {
	if v <= 0 {
		return 0
	}
	// Newton's method converges in a handful of iterations for the magnitudes here.
	x := v
	for i := 0; i < 20; i++ {
		next := 0.5 * (x + v/x)
		if next == x {
			break
		}
		x = next
	}
	return x
}
