// Package dnsmon measures DNS resolution: which resolvers answer, how quickly, and
// whether failures are the resolver's or the network's.
//
// Queries go through the Go resolver rather than a hand-rolled DNS implementation, with
// a custom dialer when a specific server must be tested. That keeps the wire handling in
// the standard library while still allowing per-server measurement, which is what
// distinguishes "our resolver is broken" from "the Internet is unreachable".
package dnsmon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Result is one resolution attempt.
type Result struct {
	Name string `json:"name"`
	// Server is the resolver queried, or "system" when the OS resolver was used.
	Server   string        `json:"server"`
	Duration time.Duration `json:"duration"`
	Answers  []string      `json:"answers,omitempty"`
	OK       bool          `json:"ok"`
	Err      error         `json:"-"`
	Error    string        `json:"error,omitempty"`
	// Protocol is udp or tcp; the Go resolver retries over TCP for truncated answers.
	Protocol string `json:"protocol,omitempty"`
	// NXDomain distinguishes "the resolver answered, and the name does not exist" from
	// "the resolver did not answer". Only the latter is a fault.
	NXDomain bool `json:"nxdomain,omitempty"`
}

// MS returns the resolution time in milliseconds.
func (r Result) MS() float64 { return float64(r.Duration) / float64(time.Millisecond) }

// Prober resolves names, optionally against specific servers.
type Prober struct {
	timeout time.Duration
	// useSystem queries through the OS resolver in addition to explicit servers.
	useSystem bool
}

// Config configures a prober.
type Config struct {
	Timeout   time.Duration
	UseSystem bool
}

// New creates a DNS prober.
func New(cfg Config) *Prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	return &Prober{timeout: cfg.Timeout, useSystem: cfg.UseSystem}
}

// SystemServer is the pseudo-server name used when the OS resolver is queried.
const SystemServer = "system"

// Resolve resolves a name using the operating system's configured resolvers.
func (p *Prober) Resolve(ctx context.Context, name string) Result {
	return p.resolveWith(ctx, name, SystemServer, net.DefaultResolver)
}

// ResolveVia resolves a name against one specific server (host:port).
//
// PreferGo forces the pure-Go resolver so the custom dialer is actually used; without it
// cgo-based resolution on some platforms would ignore the server and silently measure
// the system resolver instead.
func (p *Prober) ResolveVia(ctx context.Context, name, server string) Result {
	server = normalizeServer(server)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: p.timeout}
			// Honour the network the resolver asks for (it retries over TCP when an
			// answer is truncated).
			return d.DialContext(ctx, network, server)
		},
	}
	return p.resolveWith(ctx, name, server, r)
}

func (p *Prober) resolveWith(ctx context.Context, name, server string, r *net.Resolver) Result {
	res := Result{Name: name, Server: server, Protocol: "udp"}
	queryCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	start := time.Now()
	addrs, err := r.LookupNetIP(queryCtx, "ip", name)
	res.Duration = time.Since(start)

	if err != nil {
		res.Err = err
		res.Error = err.Error()
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// The resolver answered; the name simply does not exist. That is a
			// successful round trip as far as reachability is concerned.
			res.NXDomain = true
			res.OK = true
		}
		return res
	}
	res.OK = true
	res.Answers = make([]string, 0, len(addrs))
	for _, a := range addrs {
		res.Answers = append(res.Answers, a.Unmap().String())
	}
	sort.Strings(res.Answers)
	return res
}

// ProbeSet is the outcome of one monitoring cycle across servers.
type ProbeSet struct {
	Name      string        `json:"name"`
	Results   []Result      `json:"results"`
	Tested    int           `json:"tested"`
	Failed    int           `json:"failed"`
	Fastest   time.Duration `json:"fastest"`
	Slowest   time.Duration `json:"slowest"`
	Average   time.Duration `json:"average"`
	AnyOK     bool          `json:"any_ok"`
	AllFailed bool          `json:"all_failed"`
}

// FailedServers lists the servers that did not answer.
func (s ProbeSet) FailedServers() []string {
	var out []string
	for _, r := range s.Results {
		if !r.OK {
			out = append(out, r.Server)
		}
	}
	return out
}

// WorkingServers lists the servers that answered.
func (s ProbeSet) WorkingServers() []string {
	var out []string
	for _, r := range s.Results {
		if r.OK {
			out = append(out, r.Server)
		}
	}
	return out
}

// Probe resolves one name against the system resolver and each configured server.
func (p *Prober) Probe(ctx context.Context, name string, servers []string) ProbeSet {
	set := ProbeSet{Name: name}
	if p.useSystem {
		set.Results = append(set.Results, p.Resolve(ctx, name))
	}
	for _, s := range servers {
		if ctx.Err() != nil {
			break
		}
		set.Results = append(set.Results, p.ResolveVia(ctx, name, s))
	}
	summarise(&set)
	return set
}

func summarise(set *ProbeSet) {
	set.Tested = len(set.Results)
	var total time.Duration
	var ok int
	for _, r := range set.Results {
		if r.OK {
			ok++
			total += r.Duration
			if set.Fastest == 0 || r.Duration < set.Fastest {
				set.Fastest = r.Duration
			}
			if r.Duration > set.Slowest {
				set.Slowest = r.Duration
			}
		} else {
			set.Failed++
		}
	}
	if ok > 0 {
		set.Average = total / time.Duration(ok)
	}
	set.AnyOK = ok > 0
	set.AllFailed = set.Tested > 0 && ok == 0
}

// normalizeServer adds the standard DNS port when the caller omitted it.
func normalizeServer(server string) string {
	server = strings.TrimSpace(server)
	if _, err := netip.ParseAddr(server); err == nil {
		return net.JoinHostPort(server, "53")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, "53")
	}
	return server
}

// ServersFromAddrPorts renders resolver addresses as host:port strings.
func ServersFromAddrPorts(in []netip.AddrPort) []string {
	out := make([]string, 0, len(in))
	for _, ap := range in {
		out = append(out, ap.String())
	}
	return out
}

// ErrNoServers is returned when there is nothing to query.
var ErrNoServers = errors.New("dnsmon: no resolvers configured")

// Describe renders a probe set for a log field.
func (s ProbeSet) Describe() string {
	if s.Tested == 0 {
		return "no servers tested"
	}
	return fmt.Sprintf("%d/%d answered", s.Tested-s.Failed, s.Tested)
}
