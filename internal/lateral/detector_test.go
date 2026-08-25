package lateral

import (
	"net/netip"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Window:             2 * time.Minute,
		HostSweepThreshold: 10,
		PortScanThreshold:  8,
		FailedThreshold:    15,
		AdminPorts:         []int{22, 135, 139, 445, 3389, 5900, 5985, 5986},
		AdminSweepHosts:    4,
		Cooldown:           10 * time.Minute,
	}
}

func obs(at time.Time, host string, port int, process string, failed bool) Observation {
	return Observation{
		Time: at, Host: netip.MustParseAddr(host), Port: port,
		Process: process, PID: 4242, Exe: "/usr/bin/" + process, User: "alice",
		Failed: failed, Protocol: "tcp",
	}
}

func kinds(findings []Finding) map[FindingKind]Finding {
	out := map[FindingKind]Finding{}
	for _, f := range findings {
		out[f.Kind] = f
	}
	return out
}

// TestHostSweep is the scenario the requirements describe: one process touching many
// internal hosts in a short window.
func TestHostSweep(t *testing.T) {
	d := New(testConfig())
	now := time.Now()

	var batch []Observation
	for i := 1; i <= 14; i++ {
		batch = append(batch, obs(now, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "scanner", true))
	}
	f, ok := kinds(d.Observe(batch, now))[HostSweep]
	if !ok {
		t.Fatal("expected a host sweep finding")
	}
	if f.DistinctHosts != 14 {
		t.Errorf("DistinctHosts = %d, want 14", f.DistinctHosts)
	}
	if f.Process != "scanner" {
		t.Errorf("Process = %q", f.Process)
	}
	// Sequential addresses with failures is strong evidence, but still only "possible".
	if f.Confidence != "high" {
		t.Errorf("Confidence = %q, want high for a sequential failing sweep", f.Confidence)
	}
	if !f.Sequential {
		t.Error("expected the sequential-address pattern to be recognised")
	}
	// The language must stay careful.
	if !contains(f.Interpretation, "Possible") {
		t.Errorf("Interpretation must be phrased as a possibility: %q", f.Interpretation)
	}
	if !contains(f.Interpretation, "scanner") && !contains(f.Interpretation, "backup") {
		t.Errorf("Interpretation should acknowledge benign explanations: %q", f.Interpretation)
	}
	if len(f.Subnets) == 0 {
		t.Error("expected the touched subnets to be summarised")
	}
}

// TestBelowThresholdIsQuiet is the negative case: normal use of a few internal services
// must produce nothing.
func TestBelowThresholdIsQuiet(t *testing.T) {
	d := New(testConfig())
	now := time.Now()
	var batch []Observation
	for i := 1; i <= 5; i++ {
		batch = append(batch, obs(now, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "explorer.exe", false))
	}
	if findings := d.Observe(batch, now); len(findings) != 0 {
		t.Errorf("five internal hosts is normal use: %+v", findings)
	}
}

func TestPortScan(t *testing.T) {
	d := New(testConfig())
	now := time.Now()

	var batch []Observation
	for port := 20; port < 32; port++ {
		batch = append(batch, obs(now, "192.168.1.50", port, "probe", true))
	}
	f, ok := kinds(d.Observe(batch, now))[PortScan]
	if !ok {
		t.Fatal("expected a port scan finding")
	}
	if f.TargetHost != "192.168.1.50" {
		t.Errorf("TargetHost = %q", f.TargetHost)
	}
	if f.DistinctPorts != 12 {
		t.Errorf("DistinctPorts = %d, want 12", f.DistinctPorts)
	}
	if !f.Sequential {
		t.Error("a contiguous port range must be recognised as sequential")
	}
	if f.Confidence != "high" {
		t.Errorf("Confidence = %q", f.Confidence)
	}
}

// TestScatteredPortsAreNotSequential distinguishes an application using several services
// from a scanner walking a range.
func TestScatteredPortsAreNotSequential(t *testing.T) {
	d := New(testConfig())
	now := time.Now()
	ports := []int{80, 443, 8080, 8443, 3306, 5432, 6379, 9200, 11211}
	var batch []Observation
	for _, p := range ports {
		batch = append(batch, obs(now, "192.168.1.50", p, "app", false))
	}
	f, ok := kinds(d.Observe(batch, now))[PortScan]
	if !ok {
		t.Fatal("nine distinct ports still crosses the threshold")
	}
	if f.Sequential {
		t.Error("scattered service ports must not be reported as sequential")
	}
	// Successful connections to scattered ports is the weakest form of this signal.
	if f.Confidence != "low" {
		t.Errorf("Confidence = %q, want low for successful scattered connections", f.Confidence)
	}
}

func TestAdminProtocolSweep(t *testing.T) {
	d := New(testConfig())
	now := time.Now()

	var batch []Observation
	for i := 1; i <= 6; i++ {
		host := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()
		batch = append(batch, obs(now, host, 445, "psexec", true))
		batch = append(batch, obs(now, host, 3389, "psexec", true))
	}
	f, ok := kinds(d.Observe(batch, now))[AdminSweep]
	if !ok {
		t.Fatal("expected a remote-admin sweep finding")
	}
	if f.DistinctHosts != 6 {
		t.Errorf("DistinctHosts = %d, want 6", f.DistinctHosts)
	}
	protocols := map[string]bool{}
	for _, p := range f.AdminProtocols {
		protocols[p] = true
	}
	// The event should name services, not port numbers.
	if !protocols["SMB"] || !protocols["RDP"] {
		t.Errorf("AdminProtocols = %v, want SMB and RDP", f.AdminProtocols)
	}
	if !contains(f.Interpretation, "Possible") {
		t.Errorf("Interpretation = %q", f.Interpretation)
	}
}

func TestRepeatedFailures(t *testing.T) {
	d := New(testConfig())
	now := time.Now()

	// Many failures spread over a few hosts: below the sweep and scan thresholds, but
	// worth noting on its own.
	var batch []Observation
	for i := 0; i < 20; i++ {
		batch = append(batch, obs(now, "192.168.1.50", 445, "client", true))
		batch = append(batch, obs(now, "192.168.1.51", 445, "client", true))
	}
	f, ok := kinds(d.Observe(batch, now))[RepeatedFailures]
	if !ok {
		t.Fatal("expected a repeated-failure finding")
	}
	if f.Failed < 15 {
		t.Errorf("Failed = %d", f.Failed)
	}
	if f.Confidence != "low" {
		t.Errorf("Confidence = %q; a misconfigured client is the likeliest explanation", f.Confidence)
	}
	if !contains(f.Interpretation, "misconfigured") {
		t.Errorf("Interpretation should mention the benign explanation: %q", f.Interpretation)
	}
}

// TestAllowedProcessesAreIgnored is essential in practice: most sites run an approved
// scanner, and reporting it every day would train operators to ignore the events.
func TestAllowedProcessesAreIgnored(t *testing.T) {
	cfg := testConfig()
	cfg.AllowProcesses = []string{"nessus*", "nmap"}
	d := New(cfg)
	now := time.Now()

	var batch []Observation
	for i := 1; i <= 30; i++ {
		host := netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String()
		batch = append(batch, obs(now, host, 445, "nessus-agent", true))
		batch = append(batch, obs(now, host, 3389, "nmap", true))
	}
	if findings := d.Observe(batch, now); len(findings) != 0 {
		t.Errorf("approved scanners must be ignored: %+v", findings)
	}
	if d.Tracked() != 0 {
		t.Errorf("an allowed process should not even be tracked, tracking %d", d.Tracked())
	}
}

// TestWindowExpiry stops slow activity spread over hours from accumulating into a sweep.
func TestWindowExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.Window = time.Minute
	d := New(cfg)
	start := time.Now()

	// Six hosts now, six more ten minutes later: never more than six inside the window.
	for i := 1; i <= 6; i++ {
		d.Observe([]Observation{obs(start, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "app", false)}, start)
	}
	later := start.Add(10 * time.Minute)
	var findings []Finding
	for i := 7; i <= 12; i++ {
		findings = append(findings,
			d.Observe([]Observation{obs(later, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "app", false)}, later)...)
	}
	if len(findings) != 0 {
		t.Errorf("activity outside the window must not accumulate: %+v", findings)
	}
}

func TestCooldownSuppressesRepeats(t *testing.T) {
	d := New(testConfig())
	now := time.Now()
	var batch []Observation
	for i := 1; i <= 14; i++ {
		batch = append(batch, obs(now, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "scanner", true))
	}
	if _, ok := kinds(d.Observe(batch, now))[HostSweep]; !ok {
		t.Fatal("expected the first finding")
	}
	// Same behaviour a moment later: already reported.
	for i := range batch {
		batch[i].Time = now.Add(10 * time.Second)
	}
	if _, ok := kinds(d.Observe(batch, now.Add(10*time.Second)))[HostSweep]; ok {
		t.Error("the cooldown should suppress an immediate repeat")
	}
	// After the cooldown it may be reported again.
	for i := range batch {
		batch[i].Time = now.Add(11 * time.Minute)
	}
	if _, ok := kinds(d.Observe(batch, now.Add(11*time.Minute)))[HostSweep]; !ok {
		t.Error("expected a repeat after the cooldown")
	}
}

func TestUnattributedConnectionsAreGrouped(t *testing.T) {
	d := New(testConfig())
	now := time.Now()
	var batch []Observation
	for i := 1; i <= 14; i++ {
		o := obs(now, netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}).String(), 445, "", true)
		o.PID = 0
		batch = append(batch, o)
	}
	f, ok := kinds(d.Observe(batch, now))[HostSweep]
	if !ok {
		t.Fatal("unattributed activity must still be reported")
	}
	if f.Process != "(unattributed)" {
		t.Errorf("Process = %q", f.Process)
	}
}

func TestConfidenceGrading(t *testing.T) {
	cases := []struct {
		observed, threshold, failed int
		sequential                  bool
		want                        string
	}{
		{10, 10, 0, false, "low"},
		// Twenty successful connections is a process using the network, not probing it.
		{20, 10, 0, false, "low"},
		{10, 10, 8, false, "medium"},
		{30, 10, 20, true, "high"},
		{12, 10, 1, true, "medium"},
	}
	for _, c := range cases {
		if got := confidenceFor(c.observed, c.threshold, c.failed, c.sequential); got != c.want {
			t.Errorf("confidenceFor(%d,%d,%d,%v) = %q, want %q",
				c.observed, c.threshold, c.failed, c.sequential, got, c.want)
		}
	}
}

func TestIsSequential(t *testing.T) {
	if !isSequential([]int{20, 21, 22, 23, 24}) {
		t.Error("a contiguous range is sequential")
	}
	if isSequential([]int{80, 443, 3389, 8080}) {
		t.Error("scattered service ports are not sequential")
	}
	if isSequential([]int{1, 2}) {
		t.Error("two ports is too few to call sequential")
	}
}

func TestSubnetSummary(t *testing.T) {
	hosts := map[string]bool{
		"192.168.1.10": true, "192.168.1.20": true, "10.0.5.3": true,
	}
	subnets := subnetsOf(hosts)
	if len(subnets) != 2 {
		t.Errorf("subnets = %v, want two /24s", subnets)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
