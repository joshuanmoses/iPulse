// Package correlation infers probable cause from several signals arriving close
// together, so iPulse reports one conclusion instead of a list of symptoms.
//
// The engine is a small deterministic rule set over a sliding window of signals. There
// is no scoring, no learning and no hidden state: a rule fires when its named conditions
// are all satisfied, and the event it emits carries the evidence that satisfied them.
package correlation

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// SignalKind separates the two things the engine reasons about.
type SignalKind string

// Signal kinds.
const (
	// KindEvent is an event another component emitted.
	KindEvent SignalKind = "event"
	// KindSample is a numeric measurement.
	KindSample SignalKind = "sample"
)

// Signal is one input to the engine.
type Signal struct {
	Time time.Time
	Kind SignalKind
	// Name is the event name (SPEED_TEST_COMPLETED) or the metric name (latency_ms).
	Name string
	// Code is the event ID for event signals.
	Code int
	// Value is the measurement for sample signals.
	Value float64
	// Target is the sample dimension (interface, probe target).
	Target string
	// Fields carries the event body, so a rule can read a reported deviation.
	Fields map[string]string
	// EventID is the database row of an event signal, so contributing events can be
	// marked as absorbed once a rule explains them.
	EventID int64
}

// Window is a time-bounded view of recent signals.
type Window struct {
	mu       sync.Mutex
	duration time.Duration
	signals  []Signal
	// max bounds memory on a busy host.
	max int
}

// NewWindow creates a sliding window.
func NewWindow(duration time.Duration) *Window {
	if duration <= 0 {
		duration = 3 * time.Minute
	}
	return &Window{duration: duration, max: 4096}
}

// Add records a signal and drops anything older than the window.
func (w *Window) Add(s Signal) {
	if s.Time.IsZero() {
		s.Time = time.Now()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.signals = append(w.signals, s)
	w.trimLocked(s.Time)
}

func (w *Window) trimLocked(now time.Time) {
	cutoff := now.Add(-w.duration)
	first := 0
	for first < len(w.signals) && w.signals[first].Time.Before(cutoff) {
		first++
	}
	if first > 0 {
		w.signals = append(w.signals[:0], w.signals[first:]...)
	}
	if len(w.signals) > w.max {
		w.signals = append(w.signals[:0], w.signals[len(w.signals)-w.max:]...)
	}
}

// Snapshot returns the signals currently in the window, oldest first.
func (w *Window) Snapshot(now time.Time) []Signal {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.trimLocked(now)
	out := make([]Signal, len(w.signals))
	copy(out, w.signals)
	return out
}

// View is an immutable evaluation context built from the window, which is what rules
// are written against. Building it once per evaluation keeps rule code simple and makes
// every rule see exactly the same inputs.
type View struct {
	Now     time.Time
	Signals []Signal

	byEventCode map[int][]Signal
	byEventName map[string][]Signal
	samples     map[string][]Signal
}

// NewView builds an evaluation context.
func NewView(now time.Time, signals []Signal) *View {
	v := &View{
		Now:         now,
		Signals:     signals,
		byEventCode: map[int][]Signal{},
		byEventName: map[string][]Signal{},
		samples:     map[string][]Signal{},
	}
	for _, s := range signals {
		switch s.Kind {
		case KindEvent:
			v.byEventCode[s.Code] = append(v.byEventCode[s.Code], s)
			v.byEventName[strings.ToUpper(s.Name)] = append(v.byEventName[strings.ToUpper(s.Name)], s)
		case KindSample:
			v.samples[s.Name] = append(v.samples[s.Name], s)
		}
	}
	return v
}

// HasEvent reports whether an event with this code is in the window.
func (v *View) HasEvent(code int) bool { return len(v.byEventCode[code]) > 0 }

// HasAnyEvent reports whether any of the codes is present.
func (v *View) HasAnyEvent(codes ...int) bool {
	for _, c := range codes {
		if v.HasEvent(c) {
			return true
		}
	}
	return false
}

// Event returns the most recent event with this code.
func (v *View) Event(code int) (Signal, bool) {
	list := v.byEventCode[code]
	if len(list) == 0 {
		return Signal{}, false
	}
	return list[len(list)-1], true
}

// EventsWithCodes returns every signal for the given codes, oldest first.
func (v *View) EventsWithCodes(codes ...int) []Signal {
	var out []Signal
	for _, c := range codes {
		out = append(out, v.byEventCode[c]...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// CountEvent returns how many times an event occurred in the window.
func (v *View) CountEvent(code int) int { return len(v.byEventCode[code]) }

// Latest returns the most recent value of a metric.
func (v *View) Latest(metric string) (float64, bool) {
	list := v.samples[metric]
	if len(list) == 0 {
		return 0, false
	}
	return list[len(list)-1].Value, true
}

// Mean returns the mean of a metric over the window.
func (v *View) Mean(metric string) (float64, bool) {
	list := v.samples[metric]
	if len(list) == 0 {
		return 0, false
	}
	var sum float64
	for _, s := range list {
		sum += s.Value
	}
	return sum / float64(len(list)), true
}

// Max returns the largest value of a metric over the window.
func (v *View) Max(metric string) (float64, bool) {
	list := v.samples[metric]
	if len(list) == 0 {
		return 0, false
	}
	out := list[0].Value
	for _, s := range list[1:] {
		if s.Value > out {
			out = s.Value
		}
	}
	return out, true
}

// Field reads a field from the most recent event with the given code.
func (v *View) Field(code int, key string) (string, bool) {
	s, ok := v.Event(code)
	if !ok {
		return "", false
	}
	val, ok := s.Fields[key]
	return val, ok
}

// EventIDs returns the database ids of events matching the codes, for suppression.
func (v *View) EventIDs(codes ...int) []int64 {
	var out []int64
	seen := map[int64]bool{}
	for _, s := range v.EventsWithCodes(codes...) {
		if s.EventID == 0 || seen[s.EventID] {
			continue
		}
		seen[s.EventID] = true
		out = append(out, s.EventID)
	}
	return out
}
