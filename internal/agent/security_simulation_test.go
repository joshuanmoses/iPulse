package agent

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/platform"
)

// conn builds a connection record for the simulations.
func conn(at time.Time, remoteIP string, port int, process string, state string, internal bool) database.Connection {
	return database.Connection{
		Key:        remoteIP + ":" + strconv.Itoa(port) + "|" + process,
		FirstSeen:  at,
		LastSeen:   at,
		Protocol:   "tcp",
		LocalIP:    "192.168.1.20",
		LocalPort:  40000 + port,
		RemoteIP:   remoteIP,
		RemotePort: port,
		State:      state,
		PID:        4242,
		Process:    process,
		Exe:        "/usr/bin/" + process,
		User:       "alice",
		Internal:   internal,
	}
}

func snapshotOf(at time.Time, conns ...database.Connection) network.Snapshot {
	snap := network.Snapshot{Time: at, Connections: conns}
	for _, c := range conns {
		snap.Total++
		if c.Internal {
			snap.Internal++
		} else {
			snap.External++
		}
		if c.State == platform.StateSynSent {
			snap.Failed++
		}
		if c.Process != "" {
			snap.WithProcess++
		}
	}
	return snap
}

// TestSimulateThreatIntelligenceMatch imports a local feed and drives a connection to a
// listed address through the matcher.
func TestSimulateThreatIntelligenceMatch(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "iocs.txt")
	if err := os.WriteFile(feedPath, []byte(
		"# test feed\n203.0.113.20   # known c2\n198.51.100.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	yes := true
	a := newTestAgent(t, func(c *config.Config) {
		c.ThreatIntel.Enabled = true
		c.ThreatIntel.Feeds = []config.ThreatFeed{{
			Name: "test-feed", Type: "ioc", Format: "plain",
			Path: feedPath, Confidence: "high", Enabled: &yes,
		}}
	})
	threat := newThreatMonitor(a)
	ctx := context.Background()

	if err := threat.importFeeds(ctx); err != nil {
		t.Fatalf("import: %v", err)
	}
	imported := requireEvent(t, a, events.ThreatFeedImported)
	if imported.Fields["Source"] != "test-feed" {
		t.Errorf("Source = %q", imported.Fields["Source"])
	}
	// One address and one prefix; the comment lines are not indicators.
	if imported.Fields["Indicators"] != "2" {
		t.Errorf("Indicators = %q, want 2", imported.Fields["Indicators"])
	}

	now := time.Now()
	// An exact address match, a CIDR match, and an unrelated destination.
	snap := snapshotOf(now,
		conn(now, "203.0.113.20", 443, "example.bin", platform.StateEstablished, false),
		conn(now, "198.51.100.77", 8443, "other.bin", platform.StateEstablished, false),
		conn(now, "1.1.1.1", 443, "browser", platform.StateEstablished, false),
	)
	if err := threat.Connections(ctx, snap); err != nil {
		t.Fatalf("match: %v", err)
	}

	// A high-confidence feed produces the specific event.
	ev := requireEvent(t, a, events.KnownMaliciousDest)
	if ev.Fields["RemoteIP"] != "203.0.113.20" && ev.Fields["RemoteIP"] != "198.51.100.77" {
		t.Errorf("RemoteIP = %q", ev.Fields["RemoteIP"])
	}
	if ev.Fields["ThreatSource"] != "test-feed" {
		t.Errorf("ThreatSource = %q", ev.Fields["ThreatSource"])
	}
	if ev.Fields["Confidence"] != "High" {
		t.Errorf("Confidence = %q", ev.Fields["Confidence"])
	}
	if ev.Fields["Process"] == "" {
		t.Error("a match must name the responsible process where it is known")
	}

	// Both listed destinations matched; the unrelated one did not.
	matches, err := a.db.QueryThreatMatches(ctx, now.Add(-time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("recorded %d matches, want 2: %+v", len(matches), matches)
	}
	for _, m := range matches {
		if m.RemoteIP == "1.1.1.1" {
			t.Error("an unlisted destination must not match")
		}
		if m.Source != "test-feed" || m.Confidence != "high" {
			t.Errorf("stored match missing provenance: %+v", m)
		}
	}
}

// TestSimulateThreatIntelAllowList keeps a site's own infrastructure from being reported
// when it appears in a public feed.
func TestSimulateThreatIntelAllowList(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "iocs.txt")
	if err := os.WriteFile(feedPath, []byte("203.0.113.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yes := true
	a := newTestAgent(t, func(c *config.Config) {
		c.ThreatIntel.Enabled = true
		c.ThreatIntel.AllowList = []string{"203.0.113.0/24"}
		c.ThreatIntel.Feeds = []config.ThreatFeed{{
			Name: "test-feed", Type: "ip", Format: "plain",
			Path: feedPath, Confidence: "high", Enabled: &yes,
		}}
	})
	threat := newThreatMonitor(a)
	ctx := context.Background()
	if err := threat.importFeeds(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := threat.Connections(ctx, snapshotOf(now,
		conn(now, "203.0.113.20", 443, "app", platform.StateEstablished, false))); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, a, events.KnownMaliciousDest)
	requireNoEvent(t, a, events.ThreatIntelligenceMatch)
}

// TestSimulateFeedImportFailure checks that a broken feed is reported rather than
// silently leaving the store empty.
func TestSimulateFeedImportFailure(t *testing.T) {
	yes := true
	a := newTestAgent(t, func(c *config.Config) {
		c.ThreatIntel.Enabled = true
		c.ThreatIntel.Feeds = []config.ThreatFeed{{
			Name: "missing", Type: "ip", Format: "plain",
			Path: filepath.Join(t.TempDir(), "does-not-exist.txt"), Enabled: &yes,
		}}
	})
	threat := newThreatMonitor(a)
	if err := threat.importFeeds(context.Background()); err != nil {
		t.Fatalf("a failing feed must not fail the whole import: %v", err)
	}
	ev := requireEvent(t, a, events.ThreatFeedImportFailed)
	if ev.Fields["Source"] != "missing" {
		t.Errorf("Source = %q", ev.Fields["Source"])
	}
	if ev.Fields["Error"] == "" {
		t.Error("the failure must be described")
	}
}

// TestSimulateInternalHostScanning is the lateral-movement scenario: one process
// touching many internal hosts with failing connections.
func TestSimulateInternalHostScanning(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Lateral.Enabled = true
		c.Lateral.HostSweepThreshold = 10
		c.Lateral.Window = config.Duration(2 * time.Minute)
	})
	lat := newLateralMonitor(a)
	now := time.Now()

	var conns []database.Connection
	for i := 1; i <= 15; i++ {
		host := netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String()
		conns = append(conns, conn(now, host, 445, "scanner", platform.StateSynSent, true))
	}
	if err := lat.Connections(context.Background(), snapshotOf(now, conns...)); err != nil {
		t.Fatal(err)
	}

	ev := requireEvent(t, a, events.InternalHostSweep)
	if ev.Fields["DistinctHosts"] != "15" {
		t.Errorf("DistinctHosts = %q", ev.Fields["DistinctHosts"])
	}
	if ev.Fields["Process"] != "scanner" {
		t.Errorf("Process = %q", ev.Fields["Process"])
	}
	// The wording must stay careful: this is a possibility, not a verdict.
	interpretation := ev.Fields["Interpretation"]
	if !strings.Contains(interpretation, "Possible") {
		t.Errorf("Interpretation must be phrased as a possibility: %q", interpretation)
	}
	if strings.Contains(strings.ToLower(interpretation), "compromise detected") {
		t.Errorf("Interpretation must not assert compromise: %q", interpretation)
	}
	if ev.Fields["Confidence"] == "" {
		t.Error("a lateral finding must state its confidence")
	}
	if ev.Fields["Subnets"] == "" {
		t.Error("expected the touched subnets to be reported")
	}
}

// TestSimulatePortScanning covers many ports on one host.
func TestSimulatePortScanning(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Lateral.Enabled = true
		c.Lateral.PortScanThreshold = 10
	})
	lat := newLateralMonitor(a)
	now := time.Now()

	var conns []database.Connection
	for port := 20; port < 40; port++ {
		conns = append(conns, conn(now, "192.168.1.50", port, "probe", platform.StateSynSent, true))
	}
	if err := lat.Connections(context.Background(), snapshotOf(now, conns...)); err != nil {
		t.Fatal(err)
	}
	ev := requireEvent(t, a, events.PossiblePortScan)
	if ev.Fields["TargetHost"] != "192.168.1.50" {
		t.Errorf("TargetHost = %q", ev.Fields["TargetHost"])
	}
	if ev.Fields["Sequential"] != "true" {
		t.Errorf("Sequential = %q, want true for a contiguous range", ev.Fields["Sequential"])
	}
	if ev.Fields["Confidence"] != "High" {
		t.Errorf("Confidence = %q", ev.Fields["Confidence"])
	}
}

// TestSimulateNormalInternalUseIsQuiet is the false-positive guard that matters most for
// this family of detectors.
func TestSimulateNormalInternalUseIsQuiet(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) { c.Lateral.Enabled = true })
	lat := newLateralMonitor(a)
	now := time.Now()

	// A workstation using a file server, a printer, a NAS and a domain controller.
	conns := []database.Connection{
		conn(now, "192.168.1.10", 445, "explorer.exe", platform.StateEstablished, true),
		conn(now, "192.168.1.11", 631, "cupsd", platform.StateEstablished, true),
		conn(now, "192.168.1.12", 445, "explorer.exe", platform.StateEstablished, true),
		conn(now, "192.168.1.13", 389, "sssd", platform.StateEstablished, true),
		conn(now, "192.168.1.13", 88, "sssd", platform.StateEstablished, true),
	}
	if err := lat.Connections(context.Background(), snapshotOf(now, conns...)); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{events.InternalHostSweep, events.PossiblePortScan,
		events.RemoteAdminProtoSweep, events.RepeatedInternalFailures} {
		requireNoEvent(t, a, code)
	}
}

// TestSimulateApprovedScannerIsIgnored is what keeps these events credible at a site
// that runs its own scanner.
func TestSimulateApprovedScannerIsIgnored(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Lateral.Enabled = true
		c.Lateral.HostSweepThreshold = 10
		c.Lateral.AllowProcesses = []string{"nessus*"}
	})
	lat := newLateralMonitor(a)
	now := time.Now()

	var conns []database.Connection
	for i := 1; i <= 40; i++ {
		host := netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String()
		conns = append(conns, conn(now, host, 445, "nessus-agent", platform.StateSynSent, true))
	}
	if err := lat.Connections(context.Background(), snapshotOf(now, conns...)); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, a, events.InternalHostSweep)
	requireNoEvent(t, a, events.RemoteAdminProtoSweep)
}

// TestSimulateAdminProtocolSweep covers the SMB/RDP/SSH case the requirements call out.
func TestSimulateAdminProtocolSweep(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Lateral.Enabled = true
		c.Lateral.AdminSweepHosts = 4
		// High enough that the generic host sweep does not fire first.
		c.Lateral.HostSweepThreshold = 100
	})
	lat := newLateralMonitor(a)
	now := time.Now()

	var conns []database.Connection
	for i := 1; i <= 6; i++ {
		host := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()
		conns = append(conns,
			conn(now, host, 445, "psexec", platform.StateSynSent, true),
			conn(now, host, 3389, "psexec", platform.StateSynSent, true))
	}
	if err := lat.Connections(context.Background(), snapshotOf(now, conns...)); err != nil {
		t.Fatal(err)
	}
	ev := requireEvent(t, a, events.RemoteAdminProtoSweep)
	// The event should name services rather than port numbers.
	if !strings.Contains(ev.Fields["Protocols"], "SMB") || !strings.Contains(ev.Fields["Protocols"], "RDP") {
		t.Errorf("Protocols = %q", ev.Fields["Protocols"])
	}
	if !strings.Contains(ev.Fields["Interpretation"], "Possible") {
		t.Errorf("Interpretation = %q", ev.Fields["Interpretation"])
	}
}

// TestSimulateNewDestinationReporting drives the destination analyzer through the
// connection consumer path.
func TestSimulateNewDestinationReporting(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Destinations.Enabled = true
		c.Destinations.LearningPeriod = 0
		c.Destinations.HighVolumeMB = 1
	})
	dest := newDestinationMonitor(a)
	ctx := context.Background()
	now := time.Now()

	snap := snapshotOf(now, conn(now, "203.0.113.7", 443, "curl", platform.StateEstablished, false))
	if err := dest.Connections(ctx, snap); err != nil {
		t.Fatal(err)
	}
	ev := requireEvent(t, a, events.NewExternalDestination)
	if ev.Fields["Destination"] != "203.0.113.7:443" {
		t.Errorf("Destination = %q", ev.Fields["Destination"])
	}
	if ev.Fields["Process"] != "curl" {
		t.Errorf("Process = %q", ev.Fields["Process"])
	}
	if ev.Fields["Confidence"] == "" {
		t.Error("a destination finding must state its confidence")
	}

	// The destination is now known, so a second observation is not reported again.
	before := len(findEvents(t, a, events.NewExternalDestination))
	if err := dest.Connections(ctx, snapshotOf(now.Add(time.Minute),
		conn(now.Add(time.Minute), "203.0.113.7", 443, "curl", platform.StateEstablished, false))); err != nil {
		t.Fatal(err)
	}
	if after := len(findEvents(t, a, events.NewExternalDestination)); after != before {
		t.Errorf("a known destination was reported again (%d then %d)", before, after)
	}
}

// TestSimulateDestinationLearningPeriod is what keeps the first hours after installation
// quiet.
func TestSimulateDestinationLearningPeriod(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Destinations.Enabled = true
		c.Destinations.LearningPeriod = config.Duration(time.Hour)
	})
	dest := newDestinationMonitor(a)
	now := time.Now()
	if err := dest.Connections(context.Background(), snapshotOf(now,
		conn(now, "203.0.113.7", 9999, "curl", platform.StateEstablished, false))); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, a, events.NewExternalDestination)
	requireNoEvent(t, a, events.UnexpectedDestPort)
}
