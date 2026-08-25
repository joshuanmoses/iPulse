package logging

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

func testConfig() config.LoggingConfig {
	c := config.Default().Logging
	c.Syslog = false // no platform log in tests
	c.EventLog = false
	c.Console = false
	return c
}

func TestTextAndJSONSinks(t *testing.T) {
	dir := t.TempDir()
	l, warns, err := New(Options{Config: testConfig(), LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	defer l.Close()

	l.Emit(events.New(events.SpeedTestCompleted).WithFields(
		events.Fields{}.AddUnit("Download", 487.2, "Mbps").Add("Status", "HEALTHY")))
	l.Emit(events.New(events.InternetConnectivityLost).WithField("ProbableCause", "ISP_OR_UPSTREAM_FAILURE"))
	l.Flush()

	text, err := os.ReadFile(filepath.Join(dir, TextLogName))
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	if !strings.Contains(body, "IPULSE-1002 SPEED_TEST_COMPLETED") {
		t.Errorf("text log missing the speed test record:\n%s", body)
	}
	if !strings.Contains(body, "Download=487.2Mbps") {
		t.Errorf("text log missing fields:\n%s", body)
	}
	if !strings.Contains(body, "ERROR IPULSE-3001") {
		t.Errorf("text log missing the outage record:\n%s", body)
	}

	jl, err := os.ReadFile(filepath.Join(dir, JSONLogName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(jl)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d:\n%s", len(lines), jl)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if rec["event"] != "SPEED_TEST_COMPLETED" {
		t.Errorf("unexpected JSON record: %v", rec)
	}
}

func TestLevelFilteringAppliesToSinksNotSubscribers(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Level = "warning"
	l, _, err := New(Options{Config: cfg, LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	sub := l.Subscribe(8)
	l.Emit(events.New(events.ConnectivityCheckOK)) // DEBUG
	l.Emit(events.New(events.LatencyDegradation))  // WARNING
	l.Flush()

	text, _ := os.ReadFile(filepath.Join(dir, TextLogName))
	if strings.Contains(string(text), "CONNECTIVITY_CHECK_OK") {
		t.Error("debug event must not reach the file sink at warning level")
	}
	if !strings.Contains(string(text), "LATENCY_DEGRADATION") {
		t.Error("warning event should reach the file sink")
	}

	// Subscribers must still see everything: detection must not depend on log level.
	var got []string
	for i := 0; i < 2; i++ {
		select {
		case ev := <-sub:
			got = append(got, ev.Name)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for subscriber events, got %v", got)
		}
	}
	if len(got) != 2 {
		t.Errorf("subscriber saw %v, want both events", got)
	}
}

func TestDatabaseSinkAssignsID(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(database.Options{Path: filepath.Join(dir, "ipulse.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	l, _, err := New(Options{Config: testConfig(), LogDir: dir, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	sub := l.Subscribe(4)
	l.Emit(events.New(events.PublicIPChanged).WithField("NewIP", "203.0.113.41"))
	l.Flush()

	select {
	case ev := <-sub:
		if ev.ID == 0 {
			t.Error("published event should carry its database id so correlation can reference it")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}

	stored, err := db.QueryEvents(t.Context(), database.EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Fields["NewIP"] != "203.0.113.41" {
		t.Errorf("event not stored correctly: %+v", stored)
	}
}

func TestRotationCompressesAndPrunes(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.JSON = false
	cfg.MaxFileMB = 1 // the smallest the schema allows
	l, _, err := New(Options{Config: cfg, LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Rotation is size-driven, so drive it directly on the underlying file with a
	// small limit rather than writing a megabyte of events.
	ts := l.sinks[0].(*textSink)
	ts.f.maxBytes = 2048
	ts.f.maxArchives = 2

	for i := 0; i < 200; i++ {
		l.Emit(events.New(events.SpeedTestCompleted).
			WithField("Iteration", i).
			WithField("Padding", strings.Repeat("x", 100)))
	}
	l.Flush()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var archives, gzipped int
	for _, e := range entries {
		name := e.Name()
		if name == TextLogName {
			continue
		}
		if strings.HasPrefix(name, TextLogName+".") {
			archives++
			if strings.HasSuffix(name, ".gz") {
				gzipped++
			}
		}
	}
	if archives == 0 {
		t.Fatalf("expected rotation to produce archives, found: %v", entries)
	}
	if archives > 2 {
		t.Errorf("max_archives not enforced: %d archives", archives)
	}
	if gzipped == 0 {
		t.Error("expected archives to be compressed")
	}

	// A compressed archive must still be readable.
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			f, err := os.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("archive is not valid gzip: %v", err)
			}
			data, err := io.ReadAll(zr)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "IPULSE-1002") {
				t.Error("compressed archive lost its content")
			}
			_ = f.Close()
			break
		}
	}

	// The rotation itself must be reported as an event.
	text, _ := os.ReadFile(filepath.Join(dir, TextLogName))
	if !strings.Contains(string(text), "LOG_ROTATED") {
		t.Error("expected a LOG_ROTATED event in the current log")
	}
}

func TestLogFilePermissions(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	l, _, err := New(Options{Config: testConfig(), LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Emit(events.New(events.AgentStarted))
	l.Flush()

	st, err := os.Stat(filepath.Join(dir, TextLogName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o640 {
		t.Errorf("log file mode = %o, want 640: connection metadata must not be world-readable", perm)
	}
}

func TestEmitNeverBlocks(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	l, _, err := New(Options{Config: cfg, LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < queueDepth*2; i++ {
			l.Emit(events.New(events.SpeedTestCompleted).WithField("N", i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Emit blocked: logging must never stall a probe")
	}
	l.Flush()
	s := l.Stats()
	if s.Written == 0 {
		t.Error("expected events to be written")
	}
	if s.Written+s.Dropped < queueDepth {
		t.Errorf("counters do not add up: %+v", s)
	}
}

func TestDiscardLoggerIsSafe(t *testing.T) {
	l := Discard()
	defer l.Close()
	l.Emit(events.New(events.AgentStarted))
	l.Flush()
	if l.Stats().Written != 0 {
		t.Error("discard logger should not write")
	}
}

func TestSanitisedFieldsCannotForgeRecords(t *testing.T) {
	dir := t.TempDir()
	l, _, err := New(Options{Config: testConfig(), LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Emit(events.New(events.NewExternalDestination).
		WithField("Process", "evil\nDownload=999Mbps\n2026-01-01T00:00:00-05:00 INFO IPULSE-1002 SPEED_TEST_COMPLETED"))
	l.Flush()

	text, _ := os.ReadFile(filepath.Join(dir, TextLogName))
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly a header and one field line, got %d:\n%s", len(lines), text)
	}
	// The hostile value survives only as an escaped single-line value: no additional
	// record header exists, so a log parser sees one event, not two.
	if !strings.HasPrefix(lines[1], "Process=") {
		t.Errorf("field line was not contained: %q", lines[1])
	}
	if strings.Contains(lines[1], "\n") {
		t.Error("newline was not escaped")
	}
	if !strings.Contains(lines[1], "\\n") {
		t.Errorf("expected escaped newlines in %q", lines[1])
	}
}
