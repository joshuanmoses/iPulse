package connectivity

import "time"

// Transition is what an outage tracker decided after one observation.
type Transition int

// Transitions.
const (
	// TransitionNone means the state did not change.
	TransitionNone Transition = iota
	// TransitionOpen means an outage has started.
	TransitionOpen
	// TransitionClose means the outage has ended.
	TransitionClose
)

// Tracker turns a stream of health-check outcomes into outage transitions.
//
// Hysteresis is the entire point: a single failed probe on a busy Wi-Fi link is normal,
// and reporting an outage for it would make the log useless. An outage opens only after
// N consecutive failures and closes only after M consecutive successes, both
// configurable. The tracker is deliberately pure - no clock, no database, no logging -
// so its behaviour can be tested exhaustively.
type Tracker struct {
	failuresToOpen     int
	successesToClose   int
	consecutiveFail    int
	consecutiveOK      int
	open               bool
	openedAt           time.Time
	lastClassification Classification
}

// NewTracker creates a tracker. Values below 1 are raised to 1.
func NewTracker(failuresToOpen, successesToClose int) *Tracker {
	if failuresToOpen < 1 {
		failuresToOpen = 1
	}
	if successesToClose < 1 {
		successesToClose = 1
	}
	return &Tracker{failuresToOpen: failuresToOpen, successesToClose: successesToClose}
}

// Record folds one health-check outcome into the tracker and reports any transition.
func (t *Tracker) Record(ok bool, now time.Time) Transition {
	if ok {
		t.consecutiveFail = 0
		t.consecutiveOK++
		if t.open && t.consecutiveOK >= t.successesToClose {
			t.open = false
			t.consecutiveOK = 0
			return TransitionClose
		}
		return TransitionNone
	}

	t.consecutiveOK = 0
	t.consecutiveFail++
	if !t.open && t.consecutiveFail >= t.failuresToOpen {
		t.open = true
		t.openedAt = now
		return TransitionOpen
	}
	return TransitionNone
}

// Open reports whether an outage is currently open.
func (t *Tracker) Open() bool { return t.open }

// OpenedAt returns when the current outage started.
func (t *Tracker) OpenedAt() time.Time { return t.openedAt }

// ConsecutiveFailures returns the current failure streak.
func (t *Tracker) ConsecutiveFailures() int { return t.consecutiveFail }

// ConsecutiveSuccesses returns the current success streak.
func (t *Tracker) ConsecutiveSuccesses() int { return t.consecutiveOK }

// SetClassification records the latest cause, so a recovery event can report what the
// outage had been attributed to.
func (t *Tracker) SetClassification(c Classification) { t.lastClassification = c }

// Classification returns the last recorded cause.
func (t *Tracker) Classification() Classification { return t.lastClassification }

// Resume restores tracker state from a stored open outage, so a restart during an
// outage does not open a second record for the same event.
func (t *Tracker) Resume(openedAt time.Time, class Classification) {
	t.open = true
	t.openedAt = openedAt
	t.lastClassification = class
	t.consecutiveFail = t.failuresToOpen
}
