package correlation

import (
	"sync"
	"time"
)

// Engine evaluates the rule set against a sliding window of signals.
type Engine struct {
	mu     sync.Mutex
	window *Window
	rules  []*Rule
	// lastFired enforces each rule's cooldown.
	lastFired map[string]time.Time
	// conclusions is the set of event codes the engine itself emits, so its own output
	// can never be treated as an input signal. Without this the engine would feed on
	// itself: a conclusion is an event, and an event is a signal.
	conclusions map[int]bool
	enabled     bool
}

// NewEngine builds an engine with the given rules.
func NewEngine(window time.Duration, rules []*Rule) *Engine {
	e := &Engine{
		window:      NewWindow(window),
		rules:       rules,
		lastFired:   map[string]time.Time{},
		conclusions: map[int]bool{},
		enabled:     true,
	}
	for _, r := range rules {
		e.conclusions[r.Conclusion] = true
	}
	return e
}

// SetEnabled turns correlation on or off at runtime.
func (e *Engine) SetEnabled(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = v
}

// Observe records a signal. Signals whose code is one of the engine's own conclusions
// are ignored.
func (e *Engine) Observe(s Signal) {
	if s.Kind == KindEvent && e.conclusions[s.Code] {
		return
	}
	e.window.Add(s)
}

// Evaluate runs the rules and returns the first match, if any.
//
// Returning at most one match per evaluation is deliberate: the point of correlation is
// to replace a list of symptoms with a single conclusion, and rules are ordered from
// most specific to least so the most informative one wins.
func (e *Engine) Evaluate(now time.Time) (Match, bool) {
	e.mu.Lock()
	enabled := e.enabled
	e.mu.Unlock()
	if !enabled {
		return Match{}, false
	}

	view := NewView(now, e.window.Snapshot(now))

	for _, rule := range e.rules {
		if !e.cooldownElapsed(rule, now) {
			continue
		}
		evidence := make([]string, 0, len(rule.Requires))
		satisfied := true
		for _, cond := range rule.Requires {
			detail, ok := cond.Match(view)
			if !ok {
				satisfied = false
				break
			}
			if detail == "" {
				detail = cond.Name
			}
			evidence = append(evidence, detail)
		}
		if !satisfied {
			continue
		}

		match := Match{
			Rule:       rule,
			Time:       now,
			Cause:      rule.Cause,
			Evidence:   evidence,
			SuppressID: view.EventIDs(rule.Suppresses...),
		}
		if rule.Fields != nil {
			match.Fields = rule.Fields(view)
		}
		e.markFired(rule, now)
		return match, true
	}
	return Match{}, false
}

func (e *Engine) cooldownElapsed(rule *Rule, now time.Time) bool {
	if rule.Cooldown <= 0 {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	last, ok := e.lastFired[rule.Name]
	return !ok || now.Sub(last) >= rule.Cooldown
}

func (e *Engine) markFired(rule *Rule, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastFired[rule.Name] = now
}

// Rules returns the configured rules, for the API and documentation.
func (e *Engine) Rules() []*Rule { return e.rules }

// RuleNames lists the rule names.
func (e *Engine) RuleNames() []string {
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Name)
	}
	return out
}

// WindowSize returns the correlation window.
func (e *Engine) WindowSize() time.Duration { return e.window.duration }
