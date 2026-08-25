package database

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/events"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Options{Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenAppliesMigrations(t *testing.T) {
	db := openTestDB(t)
	if db.SchemaVersion() != SchemaVersionLatest() {
		t.Errorf("schema version = %d, want %d", db.SchemaVersion(), SchemaVersionLatest())
	}
	if db.MigrationsApplied() == 0 {
		t.Error("expected migrations to be applied on a fresh database")
	}
	counts, err := db.Counts(context.Background())
	if err != nil {
		t.Fatalf("every table must exist after migration: %v", err)
	}
	if len(counts) < 10 {
		t.Errorf("expected the full table set, got %d", len(counts))
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db1, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	_ = db1.Close()

	db2, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if db2.MigrationsApplied() != 0 {
		t.Errorf("reopening must not re-apply migrations, applied %d", db2.MigrationsApplied())
	}
}

func TestEventRoundTripAndFilters(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()

	ids := []int64{}
	for i, ev := range []events.Event{
		events.New(events.SpeedTestCompleted).WithTime(now.Add(-3*time.Minute)).
			WithField("Download", 487.2).WithField("Status", "HEALTHY"),
		events.New(events.LatencyDegradation).WithTime(now.Add(-2*time.Minute)).
			WithField("CurrentLatency", "73ms"),
		events.New(events.ThreatIntelligenceMatch).WithTime(now.Add(-1*time.Minute)).
			WithProcess("example.exe", 4132).WithDestination("203.0.113.20:443"),
	} {
		id, err := db.InsertEvent(ctx, ev)
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	if ids[2] <= ids[0] {
		t.Error("event ids must increase")
	}

	all, err := db.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 events, got %d", len(all))
	}
	if all[0].Code != events.ThreatIntelligenceMatch {
		t.Errorf("expected newest first, got %d", all[0].Code)
	}
	if all[0].Process != "example.exe" || all[0].Destination != "203.0.113.20:443" {
		t.Errorf("dimensions not persisted: %+v", all[0])
	}
	if all[0].Fields["PID"] != "4132" {
		t.Errorf("fields not persisted: %v", all[0].Fields)
	}

	warn := events.Warning
	warns, err := db.QueryEvents(ctx, EventFilter{MinSeverity: &warn})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 2 {
		t.Errorf("severity filter returned %d, want 2", len(warns))
	}

	byCode, err := db.QueryEvents(ctx, EventFilter{Codes: []int{events.SpeedTestCompleted}})
	if err != nil {
		t.Fatal(err)
	}
	if len(byCode) != 1 || byCode[0].Code != events.SpeedTestCompleted {
		t.Errorf("code filter failed: %+v", byCode)
	}

	search, err := db.QueryEvents(ctx, EventFilter{Search: "HEALTHY"})
	if err != nil {
		t.Fatal(err)
	}
	if len(search) != 1 {
		t.Errorf("text search returned %d, want 1", len(search))
	}

	// A search containing LIKE wildcards must be treated literally.
	lit, err := db.QueryEvents(ctx, EventFilter{Search: "%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lit) != 0 {
		t.Errorf("wildcard search should not match everything, got %d", len(lit))
	}

	counts, err := db.SeverityCounts(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if counts[events.Warning] != 2 || counts[events.Info] != 1 {
		t.Errorf("unexpected severity counts: %v", counts)
	}

	if err := db.MarkSuppressed(ctx, []int64{ids[1]}, "corr-1"); err != nil {
		t.Fatal(err)
	}
	visible, _ := db.QueryEvents(ctx, EventFilter{})
	if len(visible) != 2 {
		t.Errorf("suppressed events must be hidden by default, got %d", len(visible))
	}
	withSuppressed, _ := db.QueryEvents(ctx, EventFilter{IncludeSuppressed: true})
	if len(withSuppressed) != 3 {
		t.Errorf("suppressed events must still be retrievable, got %d", len(withSuppressed))
	}
}

func TestMeasurementsAndStats(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)

	var ms []Measurement
	for i := 0; i < 60; i++ {
		ms = append(ms, Measurement{
			Time: base.Add(time.Duration(i) * time.Minute), Metric: MetricLatencyMS,
			Value: float64(10 + i%5), Unit: "ms", Target: "1.1.1.1", OK: true,
		})
	}
	if err := db.InsertMeasurements(ctx, ms); err != nil {
		t.Fatal(err)
	}

	stats, err := db.MetricStats(ctx, MetricLatencyMS, "1.1.1.1", base.Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Count != 60 {
		t.Errorf("count = %d, want 60", stats.Count)
	}
	if stats.Min != 10 || stats.Max != 14 {
		t.Errorf("unexpected range: %v-%v", stats.Min, stats.Max)
	}

	latest, ok, err := db.LatestMeasurement(ctx, MetricLatencyMS, "1.1.1.1")
	if err != nil || !ok {
		t.Fatalf("latest: %v ok=%v", err, ok)
	}
	if latest.Value != 14 {
		t.Errorf("latest value = %v, want 14", latest.Value)
	}

	series, err := db.TimeSeries(ctx, MetricLatencyMS, "1.1.1.1", base.Add(-time.Minute), time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) < 5 || len(series) > 8 {
		t.Errorf("expected roughly 6 ten-minute buckets, got %d", len(series))
	}
}

func TestOutageLifecycleAndAvailability(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	start := time.Now().Add(-30 * time.Minute)

	id, err := db.OpenOutage(ctx, Outage{
		Start: start, Classification: "ISP_OUTAGE", ProbableCause: "upstream failure",
		Evidence: `{"gateway":true,"dns":true}`, Interface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A second diagnostic run while an outage is open must not create a new record.
	id2, err := db.OpenOutage(ctx, Outage{Start: start.Add(time.Minute), Classification: "ISP_OUTAGE"})
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Errorf("expected the open outage to be reused, got %d and %d", id, id2)
	}
	cur, ok, err := db.CurrentOutage(ctx)
	if err != nil || !ok {
		t.Fatalf("current outage: %v ok=%v", err, ok)
	}
	if cur.Diagnostics != 2 {
		t.Errorf("diagnostics counter = %d, want 2", cur.Diagnostics)
	}

	end := start.Add(10 * time.Minute)
	closed, err := db.CloseOutage(ctx, id, end)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Duration != 10*time.Minute {
		t.Errorf("duration = %v, want 10m", closed.Duration)
	}
	if _, ok, _ := db.CurrentOutage(ctx); ok {
		t.Error("no outage should be open after closing")
	}

	av, err := db.AvailabilitySince(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if av.Outages != 1 || av.Downtime != 10*time.Minute {
		t.Errorf("unexpected availability: %+v", av)
	}
	// 10 minutes down in a 60 minute window is about 83 % available.
	if av.Percent < 82 || av.Percent > 84 {
		t.Errorf("availability = %.2f%%, want ~83%%", av.Percent)
	}
}

func TestOngoingOutageCountsAsDowntime(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if _, err := db.OpenOutage(ctx, Outage{
		Start: time.Now().Add(-10 * time.Minute), Classification: "INTERNET_OUTAGE",
	}); err != nil {
		t.Fatal(err)
	}
	av, err := db.AvailabilitySince(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if av.Downtime < 9*time.Minute {
		t.Errorf("an unresolved outage must count as downtime, got %v", av.Downtime)
	}
}

func TestSpeedTestStoreAndSummary(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	for i, dl := range []float64{480, 500, 200, 495, 460} {
		if _, err := db.InsertSpeedTest(ctx, SpeedTest{
			Time: now.Add(-time.Duration(i) * time.Hour), Mode: SpeedModeFull,
			Provider: "http", Endpoint: "cloudflare",
			DownloadMbps: dl, UploadMbps: 42, LatencyMS: 18.6, JitterMS: 2.9,
			Status: "ok", Duration: 12 * time.Second, Streams: 4,
		}); err != nil {
			t.Fatal(err)
		}
	}
	latest, ok, err := db.LatestSpeedTest(ctx, SpeedModeFull)
	if err != nil || !ok {
		t.Fatalf("latest: %v ok=%v", err, ok)
	}
	if latest.DownloadMbps != 480 || latest.Streams != 4 || latest.Duration != 12*time.Second {
		t.Errorf("round trip lost data: %+v", latest)
	}

	sum, err := db.SpeedStats(ctx, "day", now.Add(-24*time.Hour), now, 500, 50)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Samples != 5 {
		t.Errorf("samples = %d, want 5", sum.Samples)
	}
	if sum.Download.Median != 480 {
		t.Errorf("median download = %v, want 480", sum.Download.Median)
	}
	// Four of the five samples are strictly below the 500 Mbps plan (one equals it).
	if sum.DownloadPercentBelowExpected != 80 {
		t.Errorf("percent below expected = %v, want 80", sum.DownloadPercentBelowExpected)
	}
}

func TestConnectionUpsertAccumulates(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := Connection{
		Key: "tcp|10.0.0.5:5000|203.0.113.7:443|900", FirstSeen: now.Add(-time.Minute), LastSeen: now.Add(-time.Minute),
		Protocol: "tcp", LocalIP: "10.0.0.5", LocalPort: 5000, RemoteIP: "203.0.113.7", RemotePort: 443,
		State: "ESTABLISHED", PID: 900, Process: "curl", BytesSent: 100, BytesRecv: 200,
	}
	if err := db.UpsertConnections(ctx, []Connection{c}); err != nil {
		t.Fatal(err)
	}
	c.LastSeen = now
	c.BytesSent, c.BytesRecv = 500, 900
	if err := db.UpsertConnections(ctx, []Connection{c}); err != nil {
		t.Fatal(err)
	}
	list, err := db.QueryConnections(ctx, ConnectionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one aggregated row, got %d", len(list))
	}
	if list[0].Samples != 2 || list[0].BytesSent != 500 {
		t.Errorf("upsert did not accumulate: %+v", list[0])
	}

	byProc, err := db.QueryConnections(ctx, ConnectionFilter{Process: "curl"})
	if err != nil || len(byProc) != 1 {
		t.Errorf("process filter failed: %v %d", err, len(byProc))
	}
	top, err := db.TopProcesses(ctx, now.Add(-time.Hour), 5)
	if err != nil || len(top) != 1 || top[0].Process != "curl" {
		t.Errorf("top processes failed: %v %+v", err, top)
	}
}

func TestDestinationNoveltyTracking(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	d1 := Destination{RemoteIP: "203.0.113.7", RemotePort: 443, Protocol: "tcp",
		FirstSeen: now, LastSeen: now, Contacts: 1, BytesSent: 1000, Processes: `["curl"]`}

	id, isNew, err := db.UpsertDestination(ctx, d1)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first observation must be reported as new")
	}
	_, isNew, err = db.UpsertDestination(ctx, d1)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("second observation must not be reported as new")
	}
	if err := db.SetDestinationEnrichment(ctx, id, "example.invalid", "AS64496", "Example Org", "US"); err != nil {
		t.Fatal(err)
	}
	list, err := db.QueryDestinations(ctx, DestinationFilter{OrderBy: "contacts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Contacts != 2 || list[0].BytesSent != 2000 {
		t.Errorf("accumulation failed: %+v", list)
	}
	if list[0].ASNOrg != "Example Org" || list[0].ReverseDNS != "example.invalid" {
		t.Errorf("enrichment not stored: %+v", list[0])
	}
}

func TestThreatIndicatorMatching(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	_, _, err := db.UpsertIndicators(ctx, "test-feed", []Indicator{
		{Indicator: "203.0.113.20", Kind: IndicatorIP, Confidence: ConfidenceHigh},
		{Indicator: "198.51.100.0/24", Kind: IndicatorCIDR, Confidence: ConfidenceMedium},
		{Indicator: "bad.example", Kind: IndicatorDomain, Confidence: ConfidenceHigh},
		{Indicator: "2001:db8::/32", Kind: IndicatorCIDR, Confidence: ConfidenceLow},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.20", true},
		{"203.0.113.21", false},
		{"198.51.100.77", true}, // inside the CIDR
		{"198.51.101.1", false}, // just outside
		{"2001:db8::1", true},   // IPv6 CIDR
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		addr, err := netip.ParseAddr(c.ip)
		if err != nil {
			t.Fatal(err)
		}
		m, err := db.MatchIP(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(m) > 0; got != c.want {
			t.Errorf("MatchIP(%s) matched=%v, want %v (%+v)", c.ip, got, c.want, m)
		}
	}

	// Domain matching must include parent domains.
	for _, d := range []string{"bad.example", "host.bad.example", "a.b.bad.example"} {
		m, err := db.MatchDomain(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if len(m) == 0 {
			t.Errorf("MatchDomain(%s) did not match", d)
		}
	}
	if m, _ := db.MatchDomain(ctx, "good.example"); len(m) != 0 {
		t.Errorf("unexpected domain match: %+v", m)
	}

	// Re-importing must update rather than duplicate.
	added, updated, err := db.UpsertIndicators(ctx, "test-feed", []Indicator{
		{Indicator: "203.0.113.20", Kind: IndicatorIP, Confidence: ConfidenceHigh},
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || updated != 1 {
		t.Errorf("re-import added=%d updated=%d, want 0/1", added, updated)
	}
	total, bySource, err := db.IndicatorCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || bySource["test-feed"] != 4 {
		t.Errorf("counts wrong: total=%d bySource=%v", total, bySource)
	}
}

func TestBaselinePersistence(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	row := BaselineRow{
		Metric: MetricLatencyMS, Dimension: "1.1.1.1", Bucket: "wd-14",
		Samples: 42, Mean: 18.4, M2: 120, Min: 15, Max: 26, EWMA: 18.1,
		Median: 18, MAD: 1.5, P95: 24, Established: true,
		FirstSeen: time.Now().Add(-time.Hour), UpdatedAt: time.Now(),
	}
	if err := db.SaveBaseline(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Samples = 43
	if err := db.SaveBaseline(ctx, row); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.LoadBaselines(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected one baseline row, got %d", len(loaded))
	}
	if loaded[0].Samples != 43 || !loaded[0].Established || loaded[0].Median != 18 {
		t.Errorf("baseline round trip failed: %+v", loaded[0])
	}
}

func TestPruneDeletesOldRowsAndRollsUp(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -90)
	recent := time.Now().Add(-time.Hour)

	var ms []Measurement
	for i := 0; i < 20; i++ {
		ms = append(ms, Measurement{Time: old.Add(time.Duration(i) * time.Minute),
			Metric: MetricLatencyMS, Value: 20, OK: true})
		ms = append(ms, Measurement{Time: recent.Add(time.Duration(i) * time.Minute),
			Metric: MetricLatencyMS, Value: 18, OK: true})
	}
	if err := db.InsertMeasurements(ctx, ms); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEvent(ctx, events.New(events.SpeedTestCompleted).WithTime(old)); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default().Database
	res, err := db.Prune(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.ByTable["measurements"] != 20 {
		t.Errorf("expected 20 old measurements deleted, got %d", res.ByTable["measurements"])
	}
	if res.ByTable["events"] != 1 {
		t.Errorf("expected the old event deleted, got %d", res.ByTable["events"])
	}
	if res.RowsRolledUp == 0 {
		t.Error("expected old measurements to be rolled up before deletion")
	}

	counts, err := db.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["measurements"] != 20 {
		t.Errorf("recent measurements must survive, got %d", counts["measurements"])
	}

	// Long-range charts must still see the pruned period through the roll-up.
	series, err := db.TimeSeries(ctx, MetricLatencyMS, "", old.Add(-time.Hour), time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var sawOld bool
	for _, p := range series {
		if p.Time.Before(old.Add(2 * time.Hour)) {
			sawOld = true
		}
	}
	if !sawOld {
		t.Error("expected the roll-up to preserve the pruned window in the series")
	}
}

func TestStateStore(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if _, ok, err := db.GetState(ctx, "missing"); err != nil || ok {
		t.Errorf("missing key should not be an error: ok=%v err=%v", ok, err)
	}
	if err := db.SetState(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetState(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := db.GetState(ctx, "k")
	if err != nil || !ok || v != "v2" {
		t.Errorf("got %q ok=%v err=%v", v, ok, err)
	}

	type payload struct{ N int }
	if err := db.SetStateJSON(ctx, "j", payload{N: 7}); err != nil {
		t.Fatal(err)
	}
	var out payload
	if ok, err := db.GetStateJSON(ctx, "j", &out); err != nil || !ok || out.N != 7 {
		t.Errorf("json state round trip failed: %+v ok=%v err=%v", out, ok, err)
	}
}

func TestReadOnlyOpenDoesNotMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.db")
	db, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ro, err := Open(Options{Path: path, ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer ro.Close()
	if ro.MigrationsApplied() != 0 {
		t.Error("read-only open must not migrate")
	}
	if ro.SchemaVersion() != SchemaVersionLatest() {
		t.Errorf("read-only open should still report the schema version, got %d", ro.SchemaVersion())
	}
}
