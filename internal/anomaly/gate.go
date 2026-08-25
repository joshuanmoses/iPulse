// Package anomaly holds the detection primitives shared by every iPulse detector:
// hysteresis, persistence, cooldown and the deviation rules themselves.
//
// Every detector in iPulse is a deterministic rule over stored numbers. Nothing here
// uses randomness, machine learning or an opaque score: given the same inputs, the same
// events are produced, which is what makes the detection logic reviewable.
package anomaly

import (
	"sync"
	"time"
)

// Gate applies persistence, hysteresis and cooldown to a stream of breach/clear
// observations for a keyed condition.
//
// Without it, a detector that simply compares a value to a threshold produces a stream
// of duplicate events while the condition lasts, and a burst of flapping events when the
// value hovers at the threshold. The gate turns that into: fire once after N consecutive
// breaches, stay quiet for the cooldown, and report recovery once after M consecutive
// clears.
type Gate struct {
	mu sync.Mutex

	persistence         int
	recoveryPersistence int
	cooldown            time.Duration

	states map[string]*gateState
}

type gateState struct {
	breaches    int
	clears      int
	firing      bool
	firstBreach time.Time
	lastFired   time.Time
	firedCount  int
}

// NewGate creates a gate. Values below 1 are raised to 1.
func NewGate(persistence, recoveryPersistence int, cooldown time.Duration) *Gate {
	if persistence < 1 {
		persistence = 1
	}
	if recoveryPersistence < 1 {
		recoveryPersistence = 1
	}
	return &Gate{
		persistence:         persistence,
		recoveryPersistence: recoveryPersistence,
		cooldown:            cooldown,
		states:              map[string]*gateState{},
	}
}

// Decision is what the gate concluded about one observation.
type Decision struct {
	// Fire means an event should be emitted now.
	Fire bool
	// Recovered means the condition cleared and a recovery event should be emitted.
	Recovered bool
	// Consecutive is the current streak length of the observed condition.
	Consecutive int
	// Firing reports whether the condition is currently considered active.
	Firing bool
	// Duration is how long the condition has been active (on Fire or Recovered).
	Duration time.Duration
	// Suppressed means the condition is active but the cooldown suppressed the event.
	Suppressed bool
}

// Breach records that the condition is currently true.
func (g *Gate) Breach(key string, now time.Time) Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(key)

	st.clears = 0
	st.breaches++
	if st.breaches == 1 {
		st.firstBreach = now
	}
	d := Decision{Consecutive: st.breaches, Firing: st.firing, Duration: now.Sub(st.firstBreach)}

	if st.breaches < g.persistence {
		return d
	}
	// Already reported and still inside the cooldown: stay quiet.
	if st.firing && g.cooldown > 0 && now.Sub(st.lastFired) < g.cooldown {
		d.Suppressed = true
		return d
	}
	if st.firing && g.cooldown == 0 {
		d.Suppressed = true
		return d
	}
	st.firing = true
	st.lastFired = now
	st.firedCount++
	d.Fire = true
	d.Firing = true
	return d
}

// Clear records that the condition is currently false.
func (g *Gate) Clear(key string, now time.Time) Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(key)

	st.breaches = 0
	st.clears++
	d := Decision{Consecutive: st.clears, Firing: st.firing}
	if !st.firing {
		return d
	}
	if st.clears < g.recoveryPersistence {
		return d
	}
	d.Recovered = true
	d.Firing = false
	d.Duration = now.Sub(st.firstBreach)
	st.firing = false
	st.clears = 0
	return d
}

// Observe is Breach or Clear depending on the condition.
func (g *Gate) Observe(key string, breached bool, now time.Time) Decision {
	if breached {
		return g.Breach(key, now)
	}
	return g.Clear(key, now)
}

// Firing reports whether a key is currently in the fired state.
func (g *Gate) Firing(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.states[key]
	return ok && st.firing
}

// Reset forgets a key, used when the dimension disappears (an interface is removed).
func (g *Gate) Reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.states, key)
}

// Keys returns the tracked keys, for diagnostics.
func (g *Gate) Keys() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.states))
	for k := range g.states {
		out = append(out, k)
	}
	return out
}

// Prune forgets keys that have not been observed since the cutoff, so a long-running
// agent does not accumulate state for dimensions that no longer exist.
func (g *Gate) Prune(before time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, st := range g.states {
		if st.firing {
			continue
		}
		last := st.lastFired
		if st.firstBreach.After(last) {
			last = st.firstBreach
		}
		if last.IsZero() || last.Before(before) {
			delete(g.states, k)
		}
	}
}

func (g *Gate) state(key string) *gateState {
	st, ok := g.states[key]
	if !ok {
		st = &gateState{}
		g.states[key] = st
	}
	return st
}
