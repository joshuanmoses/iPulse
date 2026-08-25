package connectivity

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	dnsmon "github.com/ipulse/ipulse/internal/dns"
	"github.com/ipulse/ipulse/internal/latency"
	"github.com/ipulse/ipulse/internal/platform"
)

// Settings is the connectivity engine's configuration, flattened from the YAML so the
// engine has no dependency on how it was expressed.
type Settings struct {
	Targets         []config.Target
	RequiredSuccess int
	IPLiterals      []string
	HTTPSTargets    []string
	DNSNames        []string
	DNSServers      []string
	FallbackDNS     []string
	GatewayMethod   string
	GatewayTCPPorts []int
	ProbeTimeout    time.Duration
	WeakSignalDBM   int
}

// Engine runs health checks and the diagnostic ladder.
type Engine struct {
	set  Settings
	plat platform.Provider
	lat  *latency.Prober
	dns  *dnsmon.Prober
	http *http.Client
}

// NewEngine builds a connectivity engine.
func NewEngine(set Settings, plat platform.Provider, lat *latency.Prober, dns *dnsmon.Prober) *Engine {
	if set.ProbeTimeout <= 0 {
		set.ProbeTimeout = 5 * time.Second
	}
	if set.RequiredSuccess <= 0 {
		set.RequiredSuccess = 1
	}
	if len(set.GatewayTCPPorts) == 0 {
		set.GatewayTCPPorts = []int{80, 443, 53}
	}
	return &Engine{
		set:  set,
		plat: plat,
		lat:  lat,
		dns:  dns,
		// Probes deliberately do not reuse connections: a pooled connection would
		// measure a path that was established minutes ago.
		http: NewHTTPClient(set.ProbeTimeout, false),
	}
}

// HealthResult is the outcome of a periodic health check.
type HealthResult struct {
	Time      time.Time     `json:"time"`
	OK        bool          `json:"ok"`
	Total     int           `json:"total"`
	Succeeded int           `json:"succeeded"`
	Required  int           `json:"required"`
	BestRTT   time.Duration `json:"best_rtt"`
	Probes    []ProbeResult `json:"probes"`
}

// Failures lists the probes that did not succeed.
func (h HealthResult) Failures() []ProbeResult {
	var out []ProbeResult
	for _, p := range h.Probes {
		if !p.OK {
			out = append(out, p)
		}
	}
	return out
}

// FailureNames renders the failed probe names for a log field.
func (h HealthResult) FailureNames() string {
	var names []string
	for _, p := range h.Failures() {
		names = append(names, p.Name+"("+p.Error+")")
	}
	sort.Strings(names)
	return joinComma(names)
}

// HealthCheck runs the cheap periodic reachability test.
//
// Probes run concurrently: the check must complete well inside its interval, and running
// three TCP handshakes in parallel costs nothing. The result is "up" as soon as the
// configured number of targets answer.
func (e *Engine) HealthCheck(ctx context.Context) HealthResult {
	res := HealthResult{Time: time.Now(), Required: e.set.RequiredSuccess}
	if len(e.set.Targets) == 0 {
		return res
	}

	type outcome struct {
		idx int
		res ProbeResult
	}
	results := make(chan outcome, len(e.set.Targets))
	for i, t := range e.set.Targets {
		go func(i int, t config.Target) {
			var pr ProbeResult
			switch t.Type {
			case "https", "http":
				pr = HTTPSProbe(ctx, e.http, t.Name, t.Address, e.set.ProbeTimeout)
			case "icmp":
				lr := e.lat.Probe(ctx, t.Address)
				pr = ProbeResult{
					Name: t.Name, Kind: ProbeICMP, Target: t.Address,
					OK: lr.OK(), Duration: lr.Avg,
				}
				if lr.Err != nil {
					pr.Err, pr.Error = lr.Err, lr.Err.Error()
				}
			default:
				pr = TCPProbe(ctx, t.Name, t.Address, e.set.ProbeTimeout)
			}
			results <- outcome{i, pr}
		}(i, t)
	}

	res.Probes = make([]ProbeResult, len(e.set.Targets))
	for i := 0; i < len(e.set.Targets); i++ {
		o := <-results
		res.Probes[o.idx] = o.res
	}
	for _, p := range res.Probes {
		res.Total++
		if p.OK {
			res.Succeeded++
			if res.BestRTT == 0 || p.Duration < res.BestRTT {
				res.BestRTT = p.Duration
			}
		}
	}
	res.OK = res.Succeeded >= e.set.RequiredSuccess
	return res
}

// Diagnosis is the full result of the diagnostic ladder.
type Diagnosis struct {
	Time           time.Time      `json:"time"`
	Duration       time.Duration  `json:"duration"`
	Classification Classification `json:"classification"`
	ProbableCause  string         `json:"probable_cause"`
	Evidence       Evidence       `json:"evidence"`
	// Steps records each rung of the ladder in order, which is what makes a diagnosis
	// auditable rather than a verdict from nowhere.
	Steps []Step `json:"steps"`
	// Trigger says why diagnostics ran.
	Trigger string `json:"trigger"`
}

// Step is one rung of the ladder.
type Step struct {
	Layer   string        `json:"layer"`
	OK      bool          `json:"ok"`
	Detail  string        `json:"detail,omitempty"`
	Elapsed time.Duration `json:"elapsed"`
}

// Diagnose runs the layered ladder: local device, interface, gateway, DNS, ISP,
// Internet. Every layer is tested even when a lower one has already failed, because the
// full picture is what makes an outage record useful afterwards; the classification then
// reports the lowest broken layer.
func (e *Engine) Diagnose(ctx context.Context, trigger string) Diagnosis {
	start := time.Now()
	d := Diagnosis{Time: start, Trigger: trigger}
	ev := &d.Evidence

	// --- Layer 1: local device ------------------------------------------------
	step := time.Now()
	ev.LoopbackOK = e.checkLoopback(ctx)
	d.Steps = append(d.Steps, Step{"local-device", ev.LoopbackOK, "loopback reachable", time.Since(step)})

	// --- Layer 2: network interface -------------------------------------------
	step = time.Now()
	iface, gwRoute := e.activeInterface()
	if iface != nil {
		ev.InterfaceName = iface.Name
		ev.InterfaceType = iface.Type
		ev.InterfaceUp = iface.Up
		ev.CarrierPresent = iface.Running
		if addr, ok := iface.PrimaryAddr(); ok {
			ev.HasRoutableAddr = true
			ev.LocalIP = addr.String()
		}
		ev.VPNActive = platform.IsTunnel(iface.Name)
	}
	if iface != nil && iface.Type == platform.IfaceWireless {
		if links, err := e.plat.Wireless(); err == nil {
			for _, l := range links {
				if l.Interface != iface.Name {
					continue
				}
				ev.WiFiAssociated = l.SSID != "" || l.SignalDBM != 0
				ev.WiFiSignalDBM = l.SignalDBM
				ev.WiFiWeak = l.SignalDBM != 0 && l.SignalDBM <= e.set.WeakSignalDBM
			}
		}
	}
	d.Steps = append(d.Steps, Step{"interface", ev.InterfaceUp && ev.HasRoutableAddr,
		fmt.Sprintf("interface=%s up=%t carrier=%t address=%s", ev.InterfaceName, ev.InterfaceUp, ev.CarrierPresent, ev.LocalIP),
		time.Since(step)})

	// --- Layer 3: default gateway ---------------------------------------------
	step = time.Now()
	if gwRoute != nil && gwRoute.Gateway.IsValid() {
		ev.DefaultRoutePresent = true
		ev.Gateway = gwRoute.Gateway.String()
		reachable, rtt, method := e.probeGateway(ctx, gwRoute.Gateway)
		ev.GatewayReachable = reachable
		ev.GatewayRTTMS = float64(rtt) / float64(time.Millisecond)
		ev.GatewayMethod = method
	} else if gwRoute != nil {
		// A default route with no next hop is normal for point-to-point links.
		ev.DefaultRoutePresent = true
		ev.GatewayReachable = true
		ev.GatewayMethod = "point-to-point"
	}
	d.Steps = append(d.Steps, Step{"gateway", ev.GatewayReachable,
		fmt.Sprintf("gateway=%s reachable=%t method=%s rtt=%.1fms", ev.Gateway, ev.GatewayReachable, ev.GatewayMethod, ev.GatewayRTTMS),
		time.Since(step)})

	// --- Layer 4: DNS ----------------------------------------------------------
	step = time.Now()
	e.diagnoseDNS(ctx, ev)
	d.Steps = append(d.Steps, Step{"dns", ev.DNSResolves,
		fmt.Sprintf("resolves=%t servers=%d/%d fallback=%t", ev.DNSResolves,
			ev.DNSServersTested-ev.DNSServersFailed, ev.DNSServersTested, ev.FallbackDNSResolves),
		time.Since(step)})

	// --- Layer 5: the ISP path, without DNS -----------------------------------
	step = time.Now()
	e.diagnoseLiterals(ctx, ev)
	d.Steps = append(d.Steps, Step{"isp", ev.ExternalIPReachable(),
		fmt.Sprintf("reachable=%d/%d", ev.IPLiteralsReachable, ev.IPLiteralsTested), time.Since(step)})

	// --- Layer 6: the Internet, full HTTPS sessions ---------------------------
	step = time.Now()
	e.diagnoseHTTPS(ctx, ev)
	d.Steps = append(d.Steps, Step{"internet", ev.HTTPSReachableAny(),
		fmt.Sprintf("reachable=%d/%d captive=%t", ev.HTTPSReachable, ev.HTTPSTested, ev.CaptivePortalSuspected),
		time.Since(step)})

	d.Classification = Classify(*ev)
	d.ProbableCause = ProbableCause(d.Classification, *ev)
	d.Duration = time.Since(start)
	return d
}

// checkLoopback verifies the local network stack. If this fails, nothing else means
// anything, and the fault is on this machine.
func (e *Engine) checkLoopback(ctx context.Context) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", ln.Addr().String())
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// activeInterface returns the interface carrying the default route, with that route.
func (e *Engine) activeInterface() (*platform.Interface, *platform.Route) {
	routes, err := e.plat.Routes()
	if err != nil {
		return e.anyUsableInterface(), nil
	}
	def, ok := platform.DefaultRoute(routes)
	if !ok {
		return e.anyUsableInterface(), nil
	}
	ifaces, err := e.plat.Interfaces()
	if err != nil {
		return nil, &def
	}
	for i := range ifaces {
		if ifaces[i].Name == def.Interface {
			return &ifaces[i], &def
		}
	}
	return nil, &def
}

// anyUsableInterface picks the most plausible active interface when there is no default
// route, so the interface layer can still be reported.
func (e *Engine) anyUsableInterface() *platform.Interface {
	ifaces, err := e.plat.Interfaces()
	if err != nil {
		return nil
	}
	var best *platform.Interface
	for i := range ifaces {
		f := &ifaces[i]
		if f.IsLoopback() || f.IsVirtual() {
			continue
		}
		if _, ok := f.PrimaryAddr(); !ok {
			continue
		}
		if best == nil || (f.Running && !best.Running) {
			best = f
		}
	}
	return best
}

// probeGateway tests the default gateway. ICMP is tried first when available; otherwise
// a TCP handshake to a small set of ports is used, and a refusal counts as reachable
// because it proves the gateway answered.
func (e *Engine) probeGateway(ctx context.Context, gw netip.Addr) (bool, time.Duration, string) {
	method := e.set.GatewayMethod
	if method == "" {
		method = "auto"
	}
	if method != "tcp" {
		res := e.lat.Probe(ctx, gw.String())
		if res.OK() {
			return true, res.Min, string(res.Method)
		}
		if method == "icmp" {
			return false, 0, "icmp"
		}
	}
	for _, port := range e.set.GatewayTCPPorts {
		addr := net.JoinHostPort(gw.String(), strconv.Itoa(port))
		pr := TCPProbe(ctx, "gateway", addr, e.set.ProbeTimeout)
		if pr.OK {
			return true, pr.Duration, "tcp/" + strconv.Itoa(port)
		}
		// A refused connection means the gateway is there and answering.
		if pr.Err != nil && isRefused(pr.Err) {
			return true, pr.Duration, "tcp-reset/" + strconv.Itoa(port)
		}
	}
	return false, 0, "tcp"
}

func (e *Engine) diagnoseDNS(ctx context.Context, ev *Evidence) {
	if len(e.set.DNSNames) == 0 {
		return
	}
	name := e.set.DNSNames[0]

	servers := e.set.DNSServers
	if len(servers) == 0 {
		if addrs, err := e.plat.DNSServers(); err == nil {
			servers = dnsmon.ServersFromAddrPorts(addrs)
		}
	}
	ev.DNSServersConfigured = len(servers)

	set := e.dns.Probe(ctx, name, servers)
	ev.DNSServersTested = set.Tested
	ev.DNSServersFailed = set.Failed
	ev.DNSResolves = set.AnyOK
	ev.DNSFailedServers = set.FailedServers()

	// When nothing configured works, try public resolvers: if they answer, the local
	// resolver is the fault, which is a different problem with a different fix.
	if !ev.DNSResolves && len(e.set.FallbackDNS) > 0 {
		fallback := e.dns.Probe(ctx, name, e.set.FallbackDNS)
		ev.FallbackDNSResolves = fallback.AnyOK
	}
}

func (e *Engine) diagnoseLiterals(ctx context.Context, ev *Evidence) {
	for _, lit := range e.set.IPLiterals {
		if ctx.Err() != nil {
			return
		}
		ev.IPLiteralsTested++
		// Port 443 on a public resolver is the most reliable DNS-free reachability
		// test available without raw sockets.
		pr := TCPProbe(ctx, lit, net.JoinHostPort(lit, "443"), e.set.ProbeTimeout)
		if pr.OK {
			ev.IPLiteralsReachable++
			continue
		}
		if pr.Err != nil && isRefused(pr.Err) {
			// The host answered, so the path works.
			ev.IPLiteralsReachable++
			continue
		}
		ev.UnreachableLiterals = append(ev.UnreachableLiterals, lit)
	}
}

func (e *Engine) diagnoseHTTPS(ctx context.Context, ev *Evidence) {
	interception := 0
	for _, url := range e.set.HTTPSTargets {
		if ctx.Err() != nil {
			return
		}
		ev.HTTPSTested++
		pr := HTTPSProbe(ctx, e.http, url, url, e.set.ProbeTimeout)
		if pr.OK {
			ev.HTTPSReachable++
			continue
		}
		ev.UnreachableHTTPS = append(ev.UnreachableHTTPS, url)
		if pr.Err != nil && isTLSInterception(pr.Err) {
			interception++
		}
	}
	// Interception is only concluded when no HTTPS session completes anywhere while
	// plain TCP still works. One endpoint with a certificate problem is that endpoint's
	// problem, not a captive portal, and reporting it as one would be a false alarm on
	// a perfectly healthy connection.
	ev.CaptivePortalSuspected = ev.HTTPSTested > 0 && ev.HTTPSReachable == 0 &&
		interception > 0 && ev.ExternalIPReachable()
}

func isRefused(err error) bool {
	return err != nil && containsAny(err.Error(), "connection refused", "reset by peer", "forcibly closed")
}

func isTLSInterception(err error) bool {
	return err != nil && containsAny(err.Error(),
		"x509", "certificate", "tls:", "handshake failure", "unknown authority")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
