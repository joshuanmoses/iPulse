// Package traffic samples interface counters and attributes throughput, including the
// traffic iPulse generates itself.
package traffic

import (
	"sync"
	"time"
)

// SelfTraffic records the bytes iPulse transfers on its own behalf, so the traffic
// monitor can exclude them.
//
// Without this, every full speed test would look like a bandwidth spike and iPulse would
// raise an anomaly for its own measurement. Transfers are recorded as intervals with a
// byte count, and a query for an arbitrary window attributes bytes proportionally to the
// overlap, which handles a test that straddles two sampling intervals.
type SelfTraffic struct {
	mu      sync.Mutex
	windows []selfWindow
	// retain bounds how much history is kept.
	retain time.Duration
}

type selfWindow struct {
	start, end time.Time
	rx, tx     int64
	reason     string
}

// NewSelfTraffic creates an accumulator that keeps the given amount of history.
func NewSelfTraffic(retain time.Duration) *SelfTraffic {
	if retain <= 0 {
		retain = 30 * time.Minute
	}
	return &SelfTraffic{retain: retain}
}

// Record adds a transfer. reason names what generated it, for reporting.
func (s *SelfTraffic) Record(start, end time.Time, rx, tx int64, reason string) {
	if end.Before(start) || (rx == 0 && tx == 0) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows = append(s.windows, selfWindow{start: start, end: end, rx: rx, tx: tx, reason: reason})
	s.pruneLocked(time.Now().Add(-s.retain))
}

// Between returns the bytes iPulse transferred within [from, to), attributing each
// recorded transfer in proportion to its overlap with the query window.
func (s *SelfTraffic) Between(from, to time.Time) (rx, tx int64) {
	if !to.After(from) {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.windows {
		overlap := overlapDuration(from, to, w.start, w.end)
		if overlap <= 0 {
			continue
		}
		total := w.end.Sub(w.start)
		if total <= 0 {
			// A zero-length record belongs entirely to any window containing it.
			rx += w.rx
			tx += w.tx
			continue
		}
		ratio := float64(overlap) / float64(total)
		rx += int64(float64(w.rx) * ratio)
		tx += int64(float64(w.tx) * ratio)
	}
	return rx, tx
}

// Active reports whether iPulse was transferring during the window, which lets a
// detector skip an interval entirely rather than trusting the subtraction.
func (s *SelfTraffic) Active(from, to time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.windows {
		if overlapDuration(from, to, w.start, w.end) > 0 {
			return true
		}
	}
	return false
}

// Prune drops records older than the cutoff.
func (s *SelfTraffic) Prune(before time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(before)
}

func (s *SelfTraffic) pruneLocked(before time.Time) {
	kept := s.windows[:0]
	for _, w := range s.windows {
		if w.end.After(before) {
			kept = append(kept, w)
		}
	}
	s.windows = kept
}

// Count returns how many transfer records are held, for diagnostics.
func (s *SelfTraffic) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.windows)
}

func overlapDuration(aStart, aEnd, bStart, bEnd time.Time) time.Duration {
	start := aStart
	if bStart.After(start) {
		start = bStart
	}
	end := aEnd
	if bEnd.Before(end) {
		end = bEnd
	}
	if !end.After(start) {
		// Treat an instantaneous record inside the window as contained.
		if !bEnd.After(bStart) && !bStart.Before(aStart) && bStart.Before(aEnd) {
			return time.Nanosecond
		}
		return 0
	}
	return end.Sub(start)
}
