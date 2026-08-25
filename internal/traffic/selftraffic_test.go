package traffic

import (
	"testing"
	"time"
)

func TestSelfTrafficProportionalAttribution(t *testing.T) {
	st := NewSelfTraffic(time.Hour)
	base := time.Now().Truncate(time.Second)

	// A 10 second transfer of 100 MB down and 20 MB up.
	st.Record(base, base.Add(10*time.Second), 100<<20, 20<<20, "speedtest")

	// The whole window sees everything.
	rx, tx := st.Between(base, base.Add(10*time.Second))
	if rx != 100<<20 || tx != 20<<20 {
		t.Errorf("full window: rx=%d tx=%d", rx, tx)
	}

	// Half the window sees half the bytes, which is what makes a sampling interval that
	// straddles a speed test come out right.
	rx, tx = st.Between(base, base.Add(5*time.Second))
	if rx < 49<<20 || rx > 51<<20 {
		t.Errorf("half window rx = %d, want about %d", rx, 50<<20)
	}
	if tx < 9<<20 || tx > 11<<20 {
		t.Errorf("half window tx = %d, want about %d", tx, 10<<20)
	}

	// A window before the transfer sees nothing.
	rx, tx = st.Between(base.Add(-time.Minute), base)
	if rx != 0 || tx != 0 {
		t.Errorf("preceding window should be empty: rx=%d tx=%d", rx, tx)
	}
	// A window after it sees nothing.
	rx, tx = st.Between(base.Add(20*time.Second), base.Add(30*time.Second))
	if rx != 0 || tx != 0 {
		t.Errorf("following window should be empty: rx=%d tx=%d", rx, tx)
	}
}

func TestSelfTrafficOverlappingRecords(t *testing.T) {
	st := NewSelfTraffic(time.Hour)
	base := time.Now()
	st.Record(base, base.Add(4*time.Second), 40, 4, "a")
	st.Record(base.Add(2*time.Second), base.Add(6*time.Second), 40, 4, "b")

	// The 2-4s window covers half of each record.
	rx, tx := st.Between(base.Add(2*time.Second), base.Add(4*time.Second))
	if rx != 40 || tx != 4 {
		t.Errorf("overlap window: rx=%d tx=%d, want 40/4", rx, tx)
	}
}

func TestSelfTrafficActive(t *testing.T) {
	st := NewSelfTraffic(time.Hour)
	base := time.Now()
	st.Record(base, base.Add(time.Second), 100, 100, "speedtest")

	if !st.Active(base, base.Add(2*time.Second)) {
		t.Error("expected the window to be reported as active")
	}
	if st.Active(base.Add(time.Minute), base.Add(2*time.Minute)) {
		t.Error("a later window must not be active")
	}
}

func TestSelfTrafficPrune(t *testing.T) {
	st := NewSelfTraffic(time.Hour)
	old := time.Now().Add(-2 * time.Hour)
	st.Record(old, old.Add(time.Second), 10, 10, "old")
	st.Record(time.Now(), time.Now().Add(time.Second), 10, 10, "new")

	st.Prune(time.Now().Add(-time.Hour))
	if st.Count() != 1 {
		t.Errorf("prune left %d records, want 1", st.Count())
	}
}

func TestSelfTrafficIgnoresEmptyRecords(t *testing.T) {
	st := NewSelfTraffic(time.Hour)
	now := time.Now()
	st.Record(now, now.Add(time.Second), 0, 0, "empty")
	st.Record(now.Add(time.Second), now, 100, 100, "reversed")
	if st.Count() != 0 {
		t.Errorf("expected empty and reversed records to be ignored, have %d", st.Count())
	}
}

func TestSelfTrafficRetentionBound(t *testing.T) {
	st := NewSelfTraffic(time.Minute)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 50; i++ {
		st.Record(base.Add(time.Duration(i)*time.Second), base.Add(time.Duration(i+1)*time.Second), 10, 10, "old")
	}
	// Recording something current prunes the old entries.
	st.Record(time.Now(), time.Now().Add(time.Second), 10, 10, "new")
	if st.Count() > 2 {
		t.Errorf("retention did not bound the history: %d records", st.Count())
	}
}
