package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/connectivity"
	dnsmon "github.com/ipulse/ipulse/internal/dns"
	"github.com/ipulse/ipulse/internal/latency"
	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/routing"
)

func init() {
	register(&command{
		Name:    "test",
		Summary: "run a test now (connectivity, dns, latency, speed)",
		Usage: `ipulse test [subcommand] [flags]

Run a test immediately and print the result. Tests run in this process using the
configured targets, so they work whether or not the service is running.

Subcommands:
  (none)         run connectivity, dns and latency
  connectivity   probe the configured reachability targets
  dns            resolve the configured names against each resolver
  latency        measure round-trip time, jitter and packet loss
  gateway        probe the default gateway
  speed          run a full speed test
  route          measure the network path to a destination
  all            run every test

Flags:
  --json    machine-readable output
  --target  override the target for latency and gateway tests`,
		Run: runTest,
	})
}

// testEnv holds the probers a CLI test needs.
type testEnv struct {
	cfg  *config.Config
	plat platform.Provider
	lat  *latency.Prober
	dns  *dnsmon.Prober
}

func newTestEnv(e *env) (*testEnv, error) {
	cfg, err := e.config()
	if err != nil {
		return nil, err
	}
	return &testEnv{
		cfg:  cfg,
		plat: platform.New(),
		lat: latency.New(latency.Config{
			Method:  latency.Method(cfg.Latency.Method),
			Probes:  cfg.Latency.Probes,
			Spacing: cfg.Latency.Spacing.D(),
			Timeout: cfg.Latency.Timeout.D(),
			TCPPort: cfg.Latency.TCPPort,
		}),
		dns: dnsmon.New(dnsmon.Config{
			Timeout:   cfg.DNS.Timeout.D(),
			UseSystem: cfg.DNS.UseSystemResolver,
		}),
	}, nil
}

func runTest(e *env, args []string) error {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := e.flags("test")
	target := fs.String("target", "", "override target")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	te, err := newTestEnv(e)
	if err != nil {
		return err
	}

	switch sub {
	case "", "quick":
		if err := e.testConnectivity(ctx, te); err != nil {
			return err
		}
		fmt.Fprintln(e.out)
		if err := e.testDNS(ctx, te); err != nil {
			return err
		}
		fmt.Fprintln(e.out)
		return e.testLatency(ctx, te, *target)
	case "connectivity", "internet":
		return e.testConnectivity(ctx, te)
	case "dns":
		return e.testDNS(ctx, te)
	case "latency", "ping":
		return e.testLatency(ctx, te, *target)
	case "gateway":
		return e.testGateway(ctx, te)
	case "route", "traceroute", "path":
		return e.testRoute(ctx, te, *target)
	case "speed":
		return e.testSpeed(ctx, te)
	case "all":
		for _, fn := range []func(context.Context, *testEnv) error{
			e.testConnectivity, e.testDNS,
			func(c context.Context, t *testEnv) error { return e.testLatency(c, t, *target) },
			e.testGateway, e.testSpeed,
		} {
			if err := fn(ctx, te); err != nil {
				return err
			}
			fmt.Fprintln(e.out)
		}
		return nil
	default:
		fmt.Fprintf(os.Stderr, "unknown test %q\n", sub)
		return errUsage
	}
}

func (e *env) testConnectivity(ctx context.Context, te *testEnv) error {
	engine := connectivity.NewEngine(settingsFrom(te.cfg), te.plat, te.lat, te.dns)
	res := engine.HealthCheck(ctx)
	if e.jsonOut {
		return e.writeJSON(res)
	}
	fmt.Fprintf(e.out, "%s\n", e.bold("Connectivity"))
	t := e.table()
	t.row("TARGET", "TYPE", "RESULT", "TIME", "DETAIL")
	for _, p := range res.Probes {
		result := e.green("ok")
		detail := p.Detail
		if !p.OK {
			result = e.red("failed")
			detail = p.Error
		}
		t.row(p.Name, string(p.Kind), result,
			fmt.Sprintf("%.1f ms", p.MS()), truncate(detail, 48))
	}
	t.flush()
	verdict := e.green("reachable")
	if !res.OK {
		verdict = e.red("unreachable")
	}
	fmt.Fprintf(e.out, "\n%d/%d targets responded (%d required): %s\n",
		res.Succeeded, res.Total, res.Required, verdict)
	return nil
}

func (e *env) testDNS(ctx context.Context, te *testEnv) error {
	cfg := te.cfg
	servers := cfg.DNS.Servers
	if len(servers) == 0 {
		if addrs, err := te.plat.DNSServers(); err == nil {
			servers = dnsmon.ServersFromAddrPorts(addrs)
		}
	}
	name := "www.google.com"
	if len(cfg.DNS.Names) > 0 {
		name = cfg.DNS.Names[0]
	}
	set := te.dns.Probe(ctx, name, servers)
	if e.jsonOut {
		return e.writeJSON(set)
	}
	fmt.Fprintf(e.out, "%s (%s)\n", e.bold("DNS"), name)
	t := e.table()
	t.row("SERVER", "RESULT", "TIME", "ANSWERS")
	for _, r := range set.Results {
		result := e.green("ok")
		answers := strings.Join(r.Answers, " ")
		if !r.OK {
			result = e.red("failed")
			answers = r.Error
		} else if r.NXDomain {
			result = e.yellow("nxdomain")
		}
		t.row(r.Server, result, fmt.Sprintf("%.1f ms", r.MS()), truncate(answers, 56))
	}
	t.flush()
	fmt.Fprintf(e.out, "\n%s, fastest %.1f ms\n", set.Describe(),
		float64(set.Fastest)/float64(time.Millisecond))
	return nil
}

func (e *env) testLatency(ctx context.Context, te *testEnv, override string) error {
	targets := te.cfg.Latency.Targets
	if override != "" {
		targets = []string{override}
	}
	results := te.lat.ProbeAll(ctx, targets)
	agg := latency.Aggregate_(results)
	if e.jsonOut {
		return e.writeJSON(agg)
	}
	fmt.Fprintf(e.out, "%s (method: %s)\n", e.bold("Latency"), te.lat.Method())
	if te.lat.Method() == latency.MethodTCP {
		fmt.Fprintf(e.out, "%s ICMP is unavailable (%v); using TCP connect timing\n",
			e.yellow("note:"), te.lat.ICMPError())
	}
	t := e.table()
	t.row("TARGET", "SENT", "RECV", "LOSS", "MIN", "AVG", "MAX", "JITTER")
	for _, r := range results {
		loss := fmt.Sprintf("%.0f%%", r.LossPct)
		if r.LossPct > 0 {
			loss = e.yellow(loss)
		}
		t.row(r.Target, fmt.Sprint(r.Sent), fmt.Sprint(r.Recv), loss,
			ms(r.Min), ms(r.Avg), ms(r.Max), ms(r.Jitter))
	}
	t.flush()
	fmt.Fprintf(e.out, "\n%d/%d targets responded, average %s, loss %.1f%%\n",
		agg.Responded, agg.Targets, ms(agg.Avg), agg.LossPct)
	return nil
}

func (e *env) testGateway(ctx context.Context, te *testEnv) error {
	routes, err := te.plat.Routes()
	if err != nil {
		return fmt.Errorf("read routing table: %w", err)
	}
	def, ok := platform.DefaultRoute(routes)
	if !ok {
		fmt.Fprintf(e.out, "%s no default route is present\n", e.red("FAIL"))
		return nil
	}
	gw := def.Gateway.String()
	if !def.Gateway.IsValid() {
		fmt.Fprintf(e.out, "%s default route via %s has no next hop (point-to-point link)\n",
			e.green("OK"), def.Interface)
		return nil
	}
	res := te.lat.Probe(ctx, gw)
	if e.jsonOut {
		return e.writeJSON(map[string]any{"gateway": gw, "interface": def.Interface, "result": res})
	}
	fmt.Fprintf(e.out, "%s\n", e.bold("Gateway"))
	e.kv([][2]string{
		{"Gateway", gw},
		{"Interface", def.Interface},
		{"Metric", fmt.Sprint(def.Metric)},
		{"Method", string(res.Method)},
		{"Reachable", boolWord(e, res.OK())},
		{"RTT", ms(res.Avg)},
		{"Loss", fmt.Sprintf("%.0f%%", res.LossPct)},
	})
	return nil
}

// testRoute measures the path to a destination.
func (e *env) testRoute(ctx context.Context, te *testEnv, override string) error {
	dest := override
	if dest == "" && len(te.cfg.Routing.Destinations) > 0 {
		dest = te.cfg.Routing.Destinations[0]
	}
	if dest == "" {
		return fmt.Errorf("no destination: pass --target or configure routing.destinations")
	}

	tracer := routing.New(routing.Config{
		MaxHops:      te.cfg.Routing.MaxHops,
		ProbesPerHop: te.cfg.Routing.ProbesPerHop,
		Timeout:      2 * time.Second,
		TotalTimeout: te.cfg.Routing.Timeout.D(),
	})
	if ok, err := tracer.Available(); !ok {
		return fmt.Errorf("path measurement is unavailable: %v", err)
	}

	path, err := tracer.Trace(ctx, dest)
	if err != nil {
		return err
	}
	if e.jsonOut {
		return e.writeJSON(path)
	}

	fmt.Fprintf(e.out, "%s to %s", e.bold("Path"), dest)
	if path.Resolved != "" && path.Resolved != dest {
		fmt.Fprintf(e.out, " (%s)", path.Resolved)
	}
	fmt.Fprintf(e.out, ", method %s\n", path.Method)

	t := e.table()
	t.row("HOP", "ADDRESS", "RTT")
	for _, h := range path.Hops {
		addr := h.Addr
		rtt := ms(h.RTT)
		if h.Addr == "" {
			addr = e.dim("*")
			rtt = e.dim("no reply")
		}
		if h.Destination {
			addr = e.green(addr)
		}
		t.row(fmt.Sprint(h.TTL), addr, rtt)
	}
	t.flush()

	if path.Complete {
		fmt.Fprintf(e.out, "\n%s reached in %d hops, %s\n", e.green("destination"), path.HopCount(), ms(path.RTT))
	} else {
		fmt.Fprintf(e.out, "\n%s not reached within %d hops\n", e.yellow("destination"), len(path.Hops))
	}
	return nil
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
}

func boolWord(e *env, ok bool) string {
	if ok {
		return e.green("yes")
	}
	return e.red("no")
}

func settingsFrom(cfg *config.Config) connectivity.Settings {
	return connectivity.Settings{
		Targets:         cfg.Connectivity.Targets,
		RequiredSuccess: cfg.Connectivity.RequiredSuccess,
		IPLiterals:      cfg.Connectivity.IPLiterals,
		HTTPSTargets:    cfg.Connectivity.HTTPSTargets,
		DNSNames:        cfg.DNS.Names,
		DNSServers:      cfg.DNS.Servers,
		FallbackDNS:     cfg.DNS.FallbackServers,
		GatewayMethod:   cfg.Connectivity.GatewayProbeMethod,
		GatewayTCPPorts: cfg.Connectivity.GatewayTCPPorts,
		ProbeTimeout:    cfg.Monitoring.ProbeTimeout.D(),
		WeakSignalDBM:   cfg.WiFi.WeakSignalDBM,
	}
}
