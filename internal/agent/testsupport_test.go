package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// newTestAgent builds a real agent against temporary directories, with everything that
// would touch the network disabled. The detection pipeline is exercised by feeding
// samples directly, which is what makes these tests deterministic and offline.
func newTestAgent(t *testing.T, tune func(*config.Config)) *Agent {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.Service.DataDir = filepath.Join(dir, "data")
	cfg.Service.LogDir = filepath.Join(dir, "logs")
	cfg.Database.Path = filepath.Join(dir, "data", "ipulse.db")
	// No collector that reaches the network is needed: samples are injected.
	cfg.SpeedTest.Enabled = false
	cfg.PublicIP.Enabled = false
	cfg.Routing.Enabled = false
	cfg.ThreatIntel.Enabled = false
	cfg.Dashboard.Enabled = false
	cfg.Logging.Syslog = false
	cfg.Logging.EventLog = false
	cfg.Logging.Console = false
	// Debug level so every event reaches the database sink the assertions read.
	cfg.Logging.Level = "debug"
	if tune != nil {
		tune(&cfg)
	}
	cfg.ResolvedPaths()
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration is invalid: %v", err)
	}

	a, err := New(Options{Config: &cfg, Mode: "test"})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown() })
	return a
}

// feed pushes samples straight into the analysis consumers, bypassing the queue so the
// test controls ordering exactly.
func feed(t *testing.T, a *Agent, samples ...sample) {
	t.Helper()
	ctx := context.Background()
	for _, c := range a.consumers {
		c.Samples(ctx, samples)
	}
}

// feedRepeated pushes the same value many times at increasing timestamps, which is how a
// baseline is built in these tests.
func feedRepeated(t *testing.T, a *Agent, metric, target string, value float64, count int, start time.Time, step time.Duration) time.Time {
	t.Helper()
	at := start
	for i := 0; i < count; i++ {
		feed(t, a, sample{Time: at, Metric: metric, Target: target, Value: value, Valid: true})
		at = at.Add(step)
	}
	return at
}

// findEvents returns the recorded events with the given code.
func findEvents(t *testing.T, a *Agent, code int) []database.StoredEvent {
	t.Helper()
	a.log.Flush()
	list, err := a.db.QueryEvents(context.Background(), database.EventFilter{
		Codes: []int{code}, Limit: 100, IncludeSuppressed: true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	return list
}

// requireEvent asserts exactly that an event was recorded, and returns the newest one.
func requireEvent(t *testing.T, a *Agent, code int) database.StoredEvent {
	t.Helper()
	list := findEvents(t, a, code)
	if len(list) == 0 {
		t.Fatalf("expected event IPULSE-%d (%s) to be recorded, found none.\nRecorded: %s",
			code, events.Name(code), recordedSummary(t, a))
	}
	return list[0]
}

// requireNoEvent asserts that an event was not recorded.
func requireNoEvent(t *testing.T, a *Agent, code int) {
	t.Helper()
	if list := findEvents(t, a, code); len(list) > 0 {
		t.Fatalf("event IPULSE-%d (%s) should not have been recorded: %s",
			code, events.Name(code), list[0].Rendered)
	}
}

// recordedSummary lists what was recorded, to make a failure diagnosable.
func recordedSummary(t *testing.T, a *Agent) string {
	t.Helper()
	list, err := a.db.QueryEvents(context.Background(), database.EventFilter{
		Limit: 50, IncludeSuppressed: true,
	})
	if err != nil {
		return "(query failed: " + err.Error() + ")"
	}
	out := ""
	for _, e := range list {
		out += "\n  " + e.Name
	}
	if out == "" {
		return "(nothing)"
	}
	return out
}
