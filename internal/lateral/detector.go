// Package lateral looks for scanning and sweep behaviour directed at the local network.
//
// The language matters here as much as the logic. iPulse reports "possible lateral
// scanning behaviour", never "compromise": the same pattern is produced by a vulnerability
// scanner, a backup agent enumerating shares, a monitoring system, and by an attacker.
// Every finding therefore carries a confidence, an interpretation in plain words, and the
// process responsible so the operator can settle the question in seconds.
package lateral

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Observation is one internal connection attempt.
type Observation struct {
	Time    time.Time
	Host    netip.Addr
	Port    int
	Process string
	PID     int
	Exe     string
	User    string
	// Failed reports that the attempt did not establish, which is the strongest
	// discriminator between scanning and normal use.
	Failed bool
	// Protocol is tcp or udp.
	Protocol string
}

// FindingKind identifies what was observed.
type FindingKind string

// Finding kinds.
const (
	HostSweep        FindingKind = "internal-host-sweep"
	PortScan         FindingKind = "possible-port-scan"
	AdminSweep       FindingKind = "remote-admin-protocol-sweep"
	RepeatedFailures FindingKind = "repeated-internal-failures"
	AbnormalLateral  FindingKind = "abnormal-lateral-connections"
)

// Finding is one report.
type Finding struct {
	Kind    FindingKind
	Time    time.Time
	Process string
	PID     int
	Exe     string
	User    string
	// Hosts and Ports summarise what was contacted.
	Hosts []string
	Ports []int
	// TargetHost is set for a port scan, which concerns one host.
	TargetHost string
	// DistinctHosts and DistinctPorts are the counts that crossed a threshold.
	DistinctHosts int
	DistinctPorts int
	Attempts      int
	Failed        int
	// Sequential reports that the ports or hosts were contacted in order, which is
	// characteristic of a scanner rather than of an application.
	Sequential bool
	Window     time.Duration
	Confidence string
	// Interpretation is the plain-language statement of what this might mean, and what
	// it does not mean.
	Interpretation string
	// Subnets lists the networks touched.
	Subnets []string
	// AdminProtocols names the remote-administration services contacted.
	AdminProtocols []string
}

// Config configures the detector.
type Config struct {
	// Window is the sliding window over which behaviour is assessed.
	Window time.Duration
	// HostSweepThreshold is the number of distinct internal hosts that raises a sweep.
	HostSweepThreshold int
	// PortScanThreshold is the number of distinct ports on one host that raises a scan.
	PortScanThreshold int
	// FailedThreshold is the number of failed internal attempts that is reported.
	FailedThreshold int
	// AdminPorts are the remote-administration ports watched for sweeps.
	AdminPorts []int
	// AdminSweepHosts is the number of hosts contacted on admin ports that raises a sweep.
	AdminSweepHosts int
	// AllowProcesses are approved scanners and management tools, which are never
	// reported. Most sites have at least one.
	AllowProcesses []string
	// Cooldown suppresses repeats for the same process and finding.
	Cooldown time.Duration
}

// Detector tracks internal connection behaviour per process.
type Detector struct {
	cfg        Config
	adminPorts map[int]bool

	mu       sync.Mutex
	tracked  map[string]*processState
	reported map[string]time.Time
}

type processState struct {
	pid      int
	exe      string
	user     string
	attempts []attempt
	// perHost records ports contacted per host, for port-scan detection.
	perHost map[string]map[int]time.Time
}

type attempt struct {
	at     time.Time
	host   string
	port   int
	failed bool
}

// New creates a detector.
func New(cfg Config) *Detector {
	if cfg.Window <= 0 {
		cfg.Window = 2 * time.Minute
	}
	if cfg.HostSweepThreshold < 2 {
		cfg.HostSweepThreshold = 20
	}
	if cfg.PortScanThreshold < 2 {
		cfg.PortScanThreshold = 15
	}
	if cfg.FailedThreshold < 2 {
		cfg.FailedThreshold = 25
	}
	if cfg.AdminSweepHosts < 2 {
		cfg.AdminSweepHosts = 5
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 10 * time.Minute
	}
	admin := make(map[int]bool, len(cfg.AdminPorts))
	for _, p := range cfg.AdminPorts {
		admin[p] = true
	}
	return &Detector{
		cfg: cfg, adminPorts: admin,
		tracked: map[string]*processState{}, reported: map[string]time.Time{},
	}
}

// Observe folds a batch of internal connection observations in and returns any findings.
func (d *Detector) Observe(obs []Observation, now time.Time) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, o := range obs {
		if !o.Host.IsValid() || o.Port <= 0 {
			continue
		}
		if d.allowed(o.Process) {
			continue
		}
		name := o.Process
		if name == "" {
			name = "(unattributed)"
		}
		st, ok := d.tracked[name]
		if !ok {
			st = &processState{perHost: map[string]map[int]time.Time{}}
			d.tracked[name] = st
		}
		if o.PID > 0 {
			st.pid = o.PID
		}
		if o.Exe != "" {
			st.exe = o.Exe
		}
		if o.User != "" {
			st.user = o.User
		}

		host := o.Host.String()
		st.attempts = append(st.attempts, attempt{at: o.Time, host: host, port: o.Port, failed: o.Failed})
		ports, ok := st.perHost[host]
		if !ok {
			ports = map[int]time.Time{}
			st.perHost[host] = ports
		}
		ports[o.Port] = o.Time
	}

	d.trim(now)
	findings := d.evaluate(now)
	d.pruneReported(now)
	return findings
}

// trim drops observations outside the window.
func (d *Detector) trim(now time.Time) {
	cutoff := now.Add(-d.cfg.Window)
	for name, st := range d.tracked {
		kept := st.attempts[:0]
		for _, a := range st.attempts {
			if a.at.After(cutoff) {
				kept = append(kept, a)
			}
		}
		st.attempts = kept

		for host, ports := range st.perHost {
			for port, at := range ports {
				if !at.After(cutoff) {
					delete(ports, port)
				}
			}
			if len(ports) == 0 {
				delete(st.perHost, host)
			}
		}
		if len(st.attempts) == 0 && len(st.perHost) == 0 {
			delete(d.tracked, name)
		}
	}
}

// evaluate applies the thresholds.
func (d *Detector) evaluate(now time.Time) []Finding {
	var findings []Finding

	names := make([]string, 0, len(d.tracked))
	for name := range d.tracked {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		st := d.tracked[name]
		hosts := map[string]bool{}
		ports := map[int]bool{}
		adminHosts := map[string]bool{}
		adminPorts := map[int]bool{}
		failed := 0
		for _, a := range st.attempts {
			hosts[a.host] = true
			ports[a.port] = true
			if a.failed {
				failed++
			}
			if d.adminPorts[a.port] {
				adminHosts[a.host] = true
				adminPorts[a.port] = true
			}
		}

		base := Finding{
			Time: now, Process: name, PID: st.pid, Exe: st.exe, User: st.user,
			Attempts: len(st.attempts), Failed: failed, Window: d.cfg.Window,
			DistinctHosts: len(hosts), DistinctPorts: len(ports),
			Hosts: sortedKeys(hosts), Ports: sortedInts(ports),
			Subnets: subnetsOf(hosts),
		}

		// A sweep across many internal hosts.
		if len(hosts) >= d.cfg.HostSweepThreshold && d.shouldReport(name, HostSweep, now) {
			f := base
			f.Kind = HostSweep
			f.Sequential = sequentialHosts(st.attempts)
			f.Confidence = confidenceFor(len(hosts), d.cfg.HostSweepThreshold, failed, f.Sequential)
			f.Interpretation = "Possible lateral scanning behaviour detected. This pattern is also " +
				"produced by vulnerability scanners, backup agents and monitoring systems; " +
				"confirm whether this process is expected to enumerate the network."
			findings = append(findings, f)
		}

		// A sweep of remote-administration ports is more specific, and more interesting -
		// but only when the attempts are failing or the host count is well past the
		// threshold. Opening shares on a handful of file servers is ordinary Windows and
		// Samba usage, and reporting it would train an operator to ignore these events.
		adminSuspicious := failed > 0 || len(adminHosts) >= d.cfg.AdminSweepHosts*2
		if len(adminHosts) >= d.cfg.AdminSweepHosts && adminSuspicious &&
			d.shouldReport(name, AdminSweep, now) {
			f := base
			f.Kind = AdminSweep
			f.DistinctHosts = len(adminHosts)
			f.Hosts = sortedKeys(adminHosts)
			f.Ports = sortedInts(adminPorts)
			f.AdminProtocols = protocolNames(adminPorts)
			f.Confidence = confidenceFor(len(adminHosts), d.cfg.AdminSweepHosts, failed, false)
			f.Interpretation = "Possible reconnaissance of remote-administration services. " +
				"Management tools and inventory scanners produce the same pattern; verify " +
				"the responsible process before treating this as an incident."
			findings = append(findings, f)
		}

		// Many ports on one host.
		for host, hostPorts := range st.perHost {
			if len(hostPorts) < d.cfg.PortScanThreshold {
				continue
			}
			if !d.shouldReport(name+"|"+host, PortScan, now) {
				continue
			}
			portList := make([]int, 0, len(hostPorts))
			for p := range hostPorts {
				portList = append(portList, p)
			}
			sort.Ints(portList)

			f := base
			f.Kind = PortScan
			f.TargetHost = host
			f.DistinctPorts = len(portList)
			f.Ports = portList
			f.Hosts = []string{host}
			f.Sequential = isSequential(portList)
			f.Confidence = confidenceFor(len(portList), d.cfg.PortScanThreshold, failed, f.Sequential)
			f.Interpretation = "Possible port-scanning behaviour toward one host. This is not " +
				"evidence of compromise on its own: confirm whether the process is an " +
				"approved scanner."
			findings = append(findings, f)
		}

		// Many failed attempts, which is what distinguishes probing from use.
		if failed >= d.cfg.FailedThreshold && d.shouldReport(name, RepeatedFailures, now) {
			f := base
			f.Kind = RepeatedFailures
			f.Confidence = "low"
			f.Interpretation = "Repeated failed connections to internal hosts. A misconfigured " +
				"client produces this as readily as discovery activity."
			findings = append(findings, f)
		}
	}
	return findings
}

// confidenceFor grades a finding.
//
// Failure rate carries the most weight, because it is what separates probing from use: a
// process that connects successfully to twenty hosts is using the network, while one
// whose attempts all fail is looking for something. Scale and sequential ordering add to
// the picture but never carry it alone.
func confidenceFor(observed, threshold, failed int, sequential bool) string {
	score := 0
	switch {
	case observed > 0 && failed == observed:
		score += 3 // every attempt failed
	case failed > observed/2:
		score += 2
	case failed > 0:
		score++
	}
	if observed >= threshold*3 {
		score += 2
	} else if observed >= threshold*2 {
		score++
	}
	if sequential {
		score++
	}
	switch {
	case score >= 4:
		return "high"
	case score >= 2:
		return "medium"
	default:
		return "low"
	}
}

// isSequential reports whether a sorted port list forms a mostly contiguous run, which
// an application does not produce but a scanner does.
func isSequential(sorted []int) bool {
	if len(sorted) < 4 {
		return false
	}
	steps := 0
	for i := 1; i < len(sorted); i++ {
		if sorted[i]-sorted[i-1] == 1 {
			steps++
		}
	}
	return steps >= (len(sorted)-1)*3/4
}

// sequentialHosts reports whether hosts were contacted in ascending address order, which
// is what an address-range sweep looks like.
func sequentialHosts(attempts []attempt) bool {
	seen := map[string]bool{}
	var order []netip.Addr
	for _, a := range attempts {
		if seen[a.host] {
			continue
		}
		seen[a.host] = true
		if addr, err := netip.ParseAddr(a.host); err == nil {
			order = append(order, addr)
		}
	}
	if len(order) < 4 {
		return false
	}
	ascending := 0
	for i := 1; i < len(order); i++ {
		if order[i].Compare(order[i-1]) > 0 {
			ascending++
		}
	}
	return ascending >= (len(order)-1)*3/4
}

func (d *Detector) allowed(process string) bool {
	if process == "" {
		return false
	}
	lower := strings.ToLower(process)
	for _, p := range d.cfg.AllowProcesses {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(lower, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if lower == p {
			return true
		}
	}
	return false
}

func (d *Detector) shouldReport(key string, kind FindingKind, now time.Time) bool {
	full := string(kind) + "|" + key
	last, ok := d.reported[full]
	if ok && now.Sub(last) < d.cfg.Cooldown {
		return false
	}
	d.reported[full] = now
	return true
}

func (d *Detector) pruneReported(now time.Time) {
	cutoff := now.Add(-4 * d.cfg.Cooldown)
	for key, at := range d.reported {
		if at.Before(cutoff) {
			delete(d.reported, key)
		}
	}
}

// adminProtocols maps the watched ports to service names, so the event says "SMB" rather
// than "445".
var adminProtocols = map[int]string{
	22:   "SSH",
	23:   "Telnet",
	135:  "RPC",
	139:  "NetBIOS",
	445:  "SMB",
	1433: "MSSQL",
	3389: "RDP",
	5900: "VNC",
	5985: "WinRM",
	5986: "WinRM-TLS",
}

func protocolNames(ports map[int]bool) []string {
	var out []string
	seen := map[string]bool{}
	list := sortedInts(ports)
	for _, p := range list {
		name, ok := adminProtocols[p]
		if !ok {
			name = "port-" + itoa(p)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// subnetsOf summarises the /24 (or /64) networks touched, which is how an operator thinks
// about a sweep.
func subnetsOf(hosts map[string]bool) []string {
	seen := map[string]bool{}
	for host := range hosts {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		bits := 24
		if addr.Is6() {
			bits = 64
		}
		if p, err := addr.Prefix(bits); err == nil {
			seen[p.String()] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// Tracked returns how many processes are being tracked, for diagnostics.
func (d *Detector) Tracked() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.tracked)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
