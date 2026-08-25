package destinations

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// memStore is an in-memory Store, so the analysis logic is tested without a database.
type memStore struct {
	seen map[string]*record
	next int64
}

type record struct {
	id        int64
	firstSeen time.Time
	contacts  int64
}

func newMemStore() *memStore { return &memStore{seen: map[string]*record{}} }

func (m *memStore) Upsert(_ context.Context, o Observation) (int64, bool, time.Time, int64, error) {
	key := o.Key()
	r, ok := m.seen[key]
	if !ok {
		m.next++
		m.seen[key] = &record{id: m.next, firstSeen: o.Time, contacts: 1}
		return m.next, true, o.Time, 1, nil
	}
	r.contacts++
	return r.id, false, r.firstSeen, r.contacts, nil
}

func (m *memStore) ContactFrequencies(context.Context) ([]float64, error) {
	out := make([]float64, 0, len(m.seen))
	for _, r := range m.seen {
		out = append(out, float64(r.contacts))
	}
	return out, nil
}

func obs(t time.Time, ip string, port int, process string, sent int64) Observation {
	return Observation{
		Time: t, RemoteIP: netip.MustParseAddr(ip), RemotePort: port, Protocol: "tcp",
		Process: process, PID: 900, BytesSent: sent, State: "ESTABLISHED",
	}
}

func testConfig() Config {
	return Config{
		LearningPeriod:  0, // learning is tested separately
		NewWindow:       24 * time.Hour,
		RarePercentile:  5,
		HighVolumeBytes: 64 << 20,
		FanoutWindow:    time.Minute,
		FanoutThreshold: 10,
		ExpectedPorts:   []int{80, 443, 53},
	}
}

func kinds(findings []Finding) map[FindingKind]Finding {
	out := map[FindingKind]Finding{}
	for _, f := range findings {
		out[f.Kind] = f
	}
	return out
}

func TestNewDestinationIsReportedOnce(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	findings, err := a.Observe(context.Background(), []Observation{obs(now, "203.0.113.7", 443, "curl", 0)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kinds(findings)[NewDestination]; !ok {
		t.Fatalf("first contact should be reported: %+v", findings)
	}

	// The same destination on the next cycle must not be reported again.
	findings, _ = a.Observe(context.Background(), []Observation{obs(now.Add(time.Minute), "203.0.113.7", 443, "curl", 0)}, now.Add(time.Minute))
	if _, ok := kinds(findings)[NewDestination]; ok {
		t.Errorf("a known destination must not be reported as new: %+v", findings)
	}
}

// TestLearningPeriodSuppressesReporting is what stops the first hours after installation
// from filling the log with "new destination" for everything the host normally talks to.
func TestLearningPeriodSuppressesReporting(t *testing.T) {
	cfg := testConfig()
	cfg.LearningPeriod = 2 * time.Hour
	now := time.Now()
	a := New(cfg, newMemStore(), now)

	if !a.Learning(now) {
		t.Fatal("analyzer should be learning immediately after start")
	}
	findings, err := a.Observe(context.Background(), []Observation{obs(now, "203.0.113.7", 9999, "curl", 1<<30)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("nothing should be reported during learning, got %+v", findings)
	}

	// After the learning period, reporting resumes.
	later := now.Add(3 * time.Hour)
	if a.Learning(later) {
		t.Fatal("learning period should have ended")
	}
	findings, _ = a.Observe(context.Background(), []Observation{obs(later, "203.0.113.8", 443, "curl", 0)}, later)
	if _, ok := kinds(findings)[NewDestination]; !ok {
		t.Errorf("expected reporting after the learning period: %+v", findings)
	}
}

// TestHighVolumeNewDestination is the combination that actually matters: novelty on its
// own is unremarkable, novelty plus a large upload is not.
func TestHighVolumeNewDestination(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	findings, err := a.Observe(context.Background(),
		[]Observation{obs(now, "203.0.113.7", 443, "sync-agent", 200<<20)}, now)
	if err != nil {
		t.Fatal(err)
	}
	byKind := kinds(findings)
	if _, ok := byKind[HighVolumeNew]; !ok {
		t.Fatalf("expected a high-volume new destination finding: %+v", findings)
	}
	if byKind[HighVolumeNew].Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", byKind[HighVolumeNew].Confidence)
	}
	// A small transfer to a new destination does not qualify.
	findings, _ = a.Observe(context.Background(),
		[]Observation{obs(now, "203.0.113.9", 443, "curl", 1024)}, now)
	if _, ok := kinds(findings)[HighVolumeNew]; ok {
		t.Error("a small transfer must not be reported as high volume")
	}
}

func TestUnexpectedPortBecomesFamiliar(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	// An unusual port on a new destination is reported.
	findings, err := a.Observe(context.Background(), []Observation{obs(now, "203.0.113.7", 4444, "app", 0)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kinds(findings)[UnexpectedPort]; !ok {
		t.Fatalf("expected an unexpected-port finding: %+v", findings)
	}

	// After enough observations the port is part of this host's normal profile.
	for i := 0; i < 6; i++ {
		at := now.Add(time.Duration(i+1) * time.Hour)
		a.Observe(context.Background(), []Observation{obs(at, "203.0.113.20", 4444, "app", 0)}, at)
	}
	at := now.Add(24 * time.Hour)
	findings, _ = a.Observe(context.Background(), []Observation{obs(at, "203.0.113.30", 4444, "app", 0)}, at)
	if _, ok := kinds(findings)[UnexpectedPort]; ok {
		t.Errorf("a port seen repeatedly should become part of the profile: %+v", findings)
	}

	// A configured expected port is never reported.
	findings, _ = a.Observe(context.Background(), []Observation{obs(at, "203.0.113.40", 443, "app", 0)}, at)
	if _, ok := kinds(findings)[UnexpectedPort]; ok {
		t.Error("a configured expected port must never be reported")
	}
}

func TestRapidFanout(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	var batch []Observation
	for i := 0; i < 12; i++ {
		batch = append(batch, obs(now, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String(), 443, "crawler", 0))
	}
	findings, err := a.Observe(context.Background(), batch, now)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := kinds(findings)[RapidFanout]
	if !ok {
		t.Fatalf("expected a fanout finding: %+v", findings)
	}
	if f.Obs.Process != "crawler" {
		t.Errorf("fanout attributed to %q", f.Obs.Process)
	}
	if f.Extra["DistinctDestinations"] != "12" {
		t.Errorf("distinct destinations = %q", f.Extra["DistinctDestinations"])
	}
	if f.Confidence != "low" {
		t.Errorf("confidence = %q; fanout alone is weak evidence", f.Confidence)
	}

	// It is not reported again within the same window.
	findings, _ = a.Observe(context.Background(), batch, now.Add(time.Second))
	if _, ok := kinds(findings)[RapidFanout]; ok {
		t.Error("fanout must not be reported repeatedly within its window")
	}
}

func TestFanoutBelowThresholdIsQuiet(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	var batch []Observation
	for i := 0; i < 5; i++ {
		batch = append(batch, obs(now, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String(), 443, "browser", 0))
	}
	findings, _ := a.Observe(context.Background(), batch, now)
	if _, ok := kinds(findings)[RapidFanout]; ok {
		t.Error("five destinations is normal browsing, not fanout")
	}
}

func TestFanoutWindowExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.FanoutWindow = time.Minute
	now := time.Now()
	a := New(cfg, newMemStore(), now.Add(-time.Hour))

	// Six destinations now and six an hour later must not combine into twelve.
	for i := 0; i < 6; i++ {
		a.Observe(context.Background(),
			[]Observation{obs(now, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String(), 443, "app", 0)}, now)
	}
	later := now.Add(time.Hour)
	var findings []Finding
	for i := 6; i < 12; i++ {
		f, _ := a.Observe(context.Background(),
			[]Observation{obs(later, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String(), 443, "app", 0)}, later)
		findings = append(findings, f...)
	}
	if _, ok := kinds(findings)[RapidFanout]; ok {
		t.Error("contacts outside the window must not accumulate into a fanout finding")
	}
}

func TestInternalDestinationsAreSkipped(t *testing.T) {
	now := time.Now()
	a := New(testConfig(), newMemStore(), now.Add(-time.Hour))

	o := obs(now, "192.168.1.50", 445, "smbclient", 0)
	o.Internal = true
	findings, err := a.Observe(context.Background(), []Observation{o}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("internal destinations belong to lateral analysis: %+v", findings)
	}
}

func TestRarityNeedsEnoughHistory(t *testing.T) {
	now := time.Now()
	store := newMemStore()
	a := New(testConfig(), store, now.Add(-time.Hour))

	// With only a handful of destinations a percentile is meaningless, so nothing is
	// reported as rare.
	for i := 0; i < 5; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		a.Observe(context.Background(),
			[]Observation{obs(at, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String(), 443, "app", 0)}, at)
	}
	// Re-observe one of them; it must not be flagged rare on such thin history.
	at := now.Add(time.Hour)
	findings, _ := a.Observe(context.Background(), []Observation{obs(at, "203.0.113.1", 443, "app", 0)}, at)
	if _, ok := kinds(findings)[RareDestination]; ok {
		t.Errorf("rarity requires enough history: %+v", findings)
	}
}

func TestStatsReportState(t *testing.T) {
	now := time.Now()
	cfg := testConfig()
	cfg.LearningPeriod = time.Hour
	a := New(cfg, newMemStore(), now)

	a.Observe(context.Background(), []Observation{obs(now, "203.0.113.7", 8443, "app", 0)}, now)
	s := a.Stats(now)
	if !s.Learning {
		t.Error("stats should report the learning period")
	}
	if s.KnownPorts == 0 {
		t.Error("expected the port profile to be populated")
	}
	if s.TrackedProcesses == 0 {
		t.Error("expected the process to be tracked for fanout")
	}
}

func TestObservationKey(t *testing.T) {
	a := obs(time.Now(), "203.0.113.7", 443, "curl", 0)
	b := obs(time.Now(), "203.0.113.7", 443, "other", 0)
	if a.Key() != b.Key() {
		t.Error("the destination key must not depend on the process")
	}
	c := obs(time.Now(), "203.0.113.7", 8443, "curl", 0)
	if a.Key() == c.Key() {
		t.Error("a different port is a different destination")
	}
}
