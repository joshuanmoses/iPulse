package tests

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/logging"
)

// TestAgentLifecycle runs a real agent against local probe targets and checks the whole
// start-up path: readiness, the start-up record, scheduled collection, state, reload and
// clean shutdown.
func TestAgentLifecycle(t *testing.T) {
	cfg := offlineConfig(t)
	a, stop := startAgent(t, cfg)
	ctx := context.Background()
	db := a.DB()

	// The start-up record must exist, and it is what an operator reads first.
	eventually(t, 10*time.Second, "the service start event", func() bool {
		return countEvents(t, db, events.AgentStarted) > 0
	})

	// Collection must actually be happening. The scheduler's own statistics are the
	// authority: a task that never ran reports zero runs regardless of what the
	// database contains.
	eventually(t, 15*time.Second, "the scheduled tasks to run", func() bool {
		ran := 0
		for _, st := range a.Scheduler().Stats() {
			if st.Runs > 0 {
				ran++
			}
		}
		return ran >= 4
	})

	for _, name := range []string{"connectivity", "latency", "dns", "interfaces"} {
		st, ok := taskStat(a.Scheduler().Stats(), name)
		if !ok {
			t.Errorf("task %q was never registered", name)
			continue
		}
		if st.Runs == 0 {
			t.Errorf("task %q never ran", name)
		}
		if st.Failures == st.Runs && st.Runs > 0 {
			t.Errorf("task %q failed on every one of its %d runs: %s", name, st.Runs, st.LastError)
		}
	}

	// Local targets are reachable, so the agent must consider the link up. Getting
	// this wrong in the other direction would mean an outage event on a healthy link.
	eventually(t, 10*time.Second, "the link to be reported online", func() bool {
		return a.State().Online()
	})

	snap := a.State().Snapshot()
	if snap.LatencyMS <= 0 {
		t.Errorf("no latency was measured: %+v", snap.LatencyMS)
	}
	if snap.StartedAt.IsZero() {
		t.Error("the start time was not recorded")
	}

	// Measurements must reach the database, not just the in-memory state.
	eventually(t, 10*time.Second, "latency measurements to be stored", func() bool {
		rows, err := db.QueryMeasurements(ctx, database.MeasurementFilter{
			Metric: "latency_ms",
			Since:  time.Now().Add(-time.Hour),
			Limit:  10,
		})
		return err == nil && len(rows) > 0
	})

	// Reload must be accepted while running, and must not disturb collection.
	before := totalRuns(a.Scheduler().Stats())
	a.Reload()
	eventually(t, 10*time.Second, "collection to continue after a reload", func() bool {
		return totalRuns(a.Scheduler().Stats()) > before
	})

	stop()

	// Shutdown must be recorded too: a gap in the data with no stop record is
	// indistinguishable from a crash. The database is closed by then, so the record is
	// read from the log file, which also proves the file sinks were writing.
	logs := mustReadFile(t, filepath.Join(cfg.Service.LogDir, logging.TextLogName))
	if !strings.Contains(logs, "AGENT_STOPPED") {
		t.Error("no agent stop record was written to the log")
	}
	if !strings.Contains(logs, "AGENT_STARTED") {
		t.Error("no agent start record was written to the log")
	}

	jsonl := mustReadFile(t, filepath.Join(cfg.Service.LogDir, logging.JSONLogName))
	var stopRecord map[string]any
	for _, line := range strings.Split(strings.TrimSpace(jsonl), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("the JSON log contains a line that is not valid JSON: %v", err)
		}
		if rec["event"] == "AGENT_STOPPED" {
			stopRecord = rec
		}
	}
	if stopRecord == nil {
		t.Fatal("the JSON log has no AGENT_STOPPED record")
	}
	// Field values are stored raw; quoting belongs to the text renderer alone. A value
	// that arrives already wrapped in quotes means rendering leaked into storage.
	fields, _ := stopRecord["fields"].(map[string]any)
	for k, v := range fields {
		str, ok := v.(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(str, `"`) && strings.HasSuffix(str, `"`) && len(str) > 1 {
			t.Errorf("field %q is stored with its rendering quotes: %s", k, str)
		}
	}
}

// TestAgentShutdownIsPrompt guards a real bug: an agent shut down before its analysis
// goroutine started used to wait out the full shutdown timeout.
func TestAgentShutdownIsPrompt(t *testing.T) {
	cfg := offlineConfig(t)
	_, stop := startAgent(t, cfg)

	start := time.Now()
	stop()
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("shutdown took %s; it should not wait out the shutdown timeout", elapsed)
	}
}

// TestUnreachableTargetsDoNotFakeAnOutage is the false-positive guard. The health-check
// target is unreachable, but the full diagnostic ladder still passes, so iPulse must
// report partial connectivity and must not open an outage. Recording an outage here
// would mean one dead probe endpoint could fabricate downtime in the availability
// figures.
func TestUnreachableTargetsDoNotFakeAnOutage(t *testing.T) {
	cfg := offlineConfig(t)
	cfg.Connectivity.Targets[0].Address = deadListener(t)
	cfg.Connectivity.FailuresBeforeOutage = 2
	revalidate(t, cfg)

	a, stop := startAgent(t, cfg)
	defer stop()
	db := a.DB()

	eventually(t, 30*time.Second, "partial connectivity to be reported", func() bool {
		return countEvents(t, db, events.PartialConnectivity) > 0
	})

	if n := countEvents(t, db, events.InternetConnectivityLost); n != 0 {
		t.Errorf("an outage was reported %d times while the diagnostic ladder was healthy", n)
	}
	list, err := db.QueryOutages(context.Background(), time.Now().Add(-time.Hour), time.Time{}, 10)
	if err != nil {
		t.Fatalf("QueryOutages: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("an outage record was created from a single unreachable probe target: %+v", list[0])
	}
}

// TestSimulatedOutageAndRecovery drives a complete outage cycle without disconnecting
// anything.
//
// The health-check target is a closed loopback port, and the diagnostic ladder's
// external reachability probes point at TEST-NET-1 (RFC 5737), which is reserved for
// documentation and is not routable anywhere. The ladder therefore concludes that
// nothing beyond this network is reachable. Recovery is produced by binding a listener
// to the port the health check was already using.
func TestSimulatedOutageAndRecovery(t *testing.T) {
	cfg := offlineConfig(t)
	addr := deadListener(t)
	cfg.Connectivity.Targets[0].Address = addr
	cfg.Connectivity.FailuresBeforeOutage = 2
	cfg.Connectivity.SuccessesBeforeRecovery = 1
	// Unroutable by definition, so the "is anything reachable off this network"
	// question has one deterministic answer.
	cfg.Connectivity.IPLiterals = []string{"192.0.2.1"}
	cfg.Connectivity.HTTPSTargets = nil
	revalidate(t, cfg)

	a, stop := startAgent(t, cfg)
	defer stop()
	db := a.DB()

	eventually(t, 60*time.Second, "connectivity loss to be reported", func() bool {
		return countEvents(t, db, events.InternetConnectivityLost) > 0
	})

	if a.State().Online() {
		t.Error("the agent still reports the link online with nothing reachable")
	}

	list, err := db.QueryOutages(context.Background(), time.Now().Add(-time.Hour), time.Time{}, 10)
	if err != nil {
		t.Fatalf("QueryOutages: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("no outage record was created")
	}
	outage := list[0]
	// The classification is allowed to vary with the host's own network; what must
	// hold is that the record carries evidence rather than a bare verdict.
	if strings.TrimSpace(outage.Classification) == "" {
		t.Error("the outage was recorded without a classification")
	}
	if strings.TrimSpace(outage.ProbableCause) == "" {
		t.Error("the outage was recorded without a probable cause")
	}
	if strings.TrimSpace(outage.Evidence) == "" {
		t.Error("the outage was recorded without the evidence that produced it")
	}
	if outage.Resolved {
		t.Error("the outage was recorded as already resolved")
	}

	// Bring the target back by listening on the port the health check is using.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not reopen %s: %v", addr, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	eventually(t, 30*time.Second, "recovery to be reported", func() bool {
		return countEvents(t, db, events.OutageEnded) > 0
	})

	if !a.State().Online() {
		t.Error("the agent still reports the link offline after the target came back")
	}

	list, err = db.QueryOutages(context.Background(), time.Now().Add(-time.Hour), time.Time{}, 10)
	if err != nil {
		t.Fatalf("QueryOutages: %v", err)
	}
	if len(list) == 0 || !list[0].Resolved {
		t.Fatal("the outage was not closed when connectivity returned")
	}
	if list[0].Duration <= 0 {
		t.Error("the closed outage has no duration, so availability accounting would be wrong")
	}
}

// TestNoInternetRequired asserts the property the whole suite depends on: with only
// loopback targets configured, the agent never attempts an outbound connection to a
// non-loopback address. It is checked by configuration rather than by packet capture,
// which is enough to catch a collector that hard-codes a public target.
func TestNoInternetRequired(t *testing.T) {
	cfg := offlineConfig(t)
	if cfg.SpeedTest.Enabled || cfg.PublicIP.Enabled || cfg.Routing.Enabled || cfg.ThreatIntel.Enabled {
		t.Fatal("the offline configuration still enables an outbound collector")
	}
	for _, target := range cfg.Connectivity.Targets {
		if !strings.HasPrefix(target.Address, "127.") {
			t.Errorf("connectivity target %q is not on loopback", target.Address)
		}
	}
	for _, target := range cfg.Latency.Targets {
		if !strings.HasPrefix(target, "127.") {
			t.Errorf("latency target %q is not on loopback", target)
		}
	}
	if len(cfg.Connectivity.HTTPSTargets) != 0 {
		t.Error("the offline configuration still has HTTPS targets")
	}
}

func countEvents(t *testing.T, db *database.DB, code int) int {
	t.Helper()
	list, err := db.QueryEvents(context.Background(), database.EventFilter{
		Since:             time.Now().Add(-time.Hour),
		Codes:             []int{code},
		IncludeSuppressed: true,
		Limit:             100,
	})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	return len(list)
}

func taskStat(stats []agent.TaskStat, name string) (agent.TaskStat, bool) {
	for _, st := range stats {
		if st.Name == name {
			return st, true
		}
	}
	return agent.TaskStat{}, false
}

func totalRuns(stats []agent.TaskStat) int64 {
	var n int64
	for _, st := range stats {
		n += st.Runs
	}
	return n
}

// revalidate applies normalisation and validation after a test has altered a
// configuration, so a test can never run against a configuration the agent itself would
// refuse.
func revalidate(t *testing.T, cfg *config.Config) {
	t.Helper()
	cfg.Normalize()
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("configuration: %v", err)
	}
}
