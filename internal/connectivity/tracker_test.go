package connectivity

import (
	"testing"
	"time"
)

// TestTrackerHysteresis is the anti-flap property: one bad probe must not open an
// outage, and one good probe must not close one.
func TestTrackerHysteresis(t *testing.T) {
	tr := NewTracker(2, 2)
	now := time.Now()

	if got := tr.Record(true, now); got != TransitionNone {
		t.Errorf("healthy start should not transition, got %v", got)
	}
	if got := tr.Record(false, now.Add(time.Second)); got != TransitionNone {
		t.Errorf("a single failure must not open an outage, got %v", got)
	}
	if tr.Open() {
		t.Error("outage opened too early")
	}
	if got := tr.Record(false, now.Add(2*time.Second)); got != TransitionOpen {
		t.Errorf("second consecutive failure should open the outage, got %v", got)
	}
	if !tr.Open() {
		t.Error("tracker should report an open outage")
	}
	// Further failures must not re-open it.
	for i := 0; i < 5; i++ {
		if got := tr.Record(false, now.Add(time.Duration(3+i)*time.Second)); got != TransitionNone {
			t.Errorf("repeat failure %d produced %v", i, got)
		}
	}
	if got := tr.Record(true, now.Add(10*time.Second)); got != TransitionNone {
		t.Errorf("a single success must not close the outage, got %v", got)
	}
	if got := tr.Record(true, now.Add(11*time.Second)); got != TransitionClose {
		t.Errorf("second consecutive success should close the outage, got %v", got)
	}
	if tr.Open() {
		t.Error("outage should be closed")
	}
}

// TestTrackerFlapping is the case hysteresis exists for: alternating results must never
// produce an outage record.
func TestTrackerFlapping(t *testing.T) {
	tr := NewTracker(3, 2)
	now := time.Now()
	for i := 0; i < 20; i++ {
		got := tr.Record(i%2 == 0, now.Add(time.Duration(i)*time.Second))
		if got != TransitionNone {
			t.Fatalf("flapping produced a transition at step %d: %v", i, got)
		}
	}
}

func TestTrackerImmediateMode(t *testing.T) {
	tr := NewTracker(1, 1)
	now := time.Now()
	if got := tr.Record(false, now); got != TransitionOpen {
		t.Errorf("with persistence 1 the first failure should open, got %v", got)
	}
	if got := tr.Record(true, now.Add(time.Second)); got != TransitionClose {
		t.Errorf("with recovery 1 the first success should close, got %v", got)
	}
}

func TestTrackerRejectsInvalidThresholds(t *testing.T) {
	tr := NewTracker(0, -5)
	now := time.Now()
	if got := tr.Record(false, now); got != TransitionOpen {
		t.Errorf("thresholds below 1 should behave as 1, got %v", got)
	}
}

func TestTrackerResume(t *testing.T) {
	tr := NewTracker(2, 2)
	start := time.Now().Add(-10 * time.Minute)
	tr.Resume(start, ClassISPOutage)

	if !tr.Open() || !tr.OpenedAt().Equal(start) {
		t.Errorf("resume did not restore the open outage: open=%v at=%v", tr.Open(), tr.OpenedAt())
	}
	if tr.Classification() != ClassISPOutage {
		t.Errorf("resume lost the classification: %s", tr.Classification())
	}
	// A resumed outage must still require the full recovery streak to close.
	if got := tr.Record(true, time.Now()); got != TransitionNone {
		t.Errorf("resumed outage closed too early: %v", got)
	}
	if got := tr.Record(true, time.Now()); got != TransitionClose {
		t.Errorf("resumed outage should close after the recovery streak, got %v", got)
	}
}

func TestTrackerCounters(t *testing.T) {
	tr := NewTracker(3, 3)
	now := time.Now()
	tr.Record(false, now)
	tr.Record(false, now)
	if tr.ConsecutiveFailures() != 2 {
		t.Errorf("failure streak = %d, want 2", tr.ConsecutiveFailures())
	}
	tr.Record(true, now)
	if tr.ConsecutiveFailures() != 0 || tr.ConsecutiveSuccesses() != 1 {
		t.Errorf("streaks not reset: fail=%d ok=%d", tr.ConsecutiveFailures(), tr.ConsecutiveSuccesses())
	}
}
