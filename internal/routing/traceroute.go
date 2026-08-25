// Package routing measures the network path to selected destinations and reports
// significant changes to it.
//
// Path measurement is the one thing iPulse does that generates traffic other systems
// notice, so it is deliberately frugal: a small number of probes, on a long interval, to
// a short list of stable destinations. A route change is reported as a notice with the
// before and after paths, because ISP re-routing is normal and only becomes interesting
// when it coincides with a latency change.
package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Hop is one step along the path.
type Hop struct {
	// TTL is the hop number.
	TTL int `json:"ttl"`
	// Addr is the responding address, empty when the hop did not answer.
	Addr string `json:"address,omitempty"`
	// RTT is the round trip to this hop.
	RTT time.Duration `json:"rtt,omitempty"`
	// Timeout reports that no reply arrived within the timeout.
	Timeout bool `json:"timeout,omitempty"`
	// Destination marks the hop that is the target itself.
	Destination bool `json:"destination,omitempty"`
}

// Path is a completed measurement.
type Path struct {
	Destination string        `json:"destination"`
	Resolved    string        `json:"resolved,omitempty"`
	Hops        []Hop         `json:"hops"`
	Complete    bool          `json:"complete"`
	Duration    time.Duration `json:"duration"`
	Method      string        `json:"method"`
	// RTT is the round trip to the destination when it was reached.
	RTT time.Duration `json:"rtt,omitempty"`
}

// HopCount returns the number of hops to the destination, or the number probed when the
// destination was not reached.
func (p Path) HopCount() int {
	for _, h := range p.Hops {
		if h.Destination {
			return h.TTL
		}
	}
	return len(p.Hops)
}

// Signature renders the responding hops as a comparable string, which is what a route
// change is detected from.
func (p Path) Signature() string {
	parts := make([]string, 0, len(p.Hops))
	for _, h := range p.Hops {
		if h.Addr == "" {
			parts = append(parts, "*")
			continue
		}
		parts = append(parts, h.Addr)
	}
	return strings.Join(parts, " ")
}

// Addresses returns the responding hop addresses in order.
func (p Path) Addresses() []string {
	var out []string
	for _, h := range p.Hops {
		if h.Addr != "" {
			out = append(out, h.Addr)
		}
	}
	return out
}

// Config configures the tracer.
type Config struct {
	MaxHops      int
	ProbesPerHop int
	// Timeout bounds one probe.
	Timeout time.Duration
	// TotalTimeout bounds the whole measurement.
	TotalTimeout time.Duration
}

// Tracer measures paths using ICMP echo with an increasing TTL.
//
// An unprivileged datagram ICMP socket is used where the platform allows it, which is
// how iPulse measures paths without asking for elevated rights on a typical Linux host.
// Where no ICMP socket can be opened at all, path measurement reports itself unavailable
// rather than silently producing nothing.
type Tracer struct {
	cfg Config

	mu        sync.Mutex
	available *bool
	availErr  error
}

// New creates a tracer.
func New(cfg Config) *Tracer {
	if cfg.MaxHops <= 0 || cfg.MaxHops > 64 {
		cfg.MaxHops = 20
	}
	if cfg.ProbesPerHop <= 0 {
		cfg.ProbesPerHop = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.TotalTimeout <= 0 {
		cfg.TotalTimeout = 30 * time.Second
	}
	return &Tracer{cfg: cfg}
}

// ErrUnavailable means no ICMP socket could be opened.
var ErrUnavailable = errors.New("routing: ICMP sockets are not permitted for this process")

// Available reports whether path measurement can run, and why not when it cannot.
func (t *Tracer) Available() (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.available != nil {
		return *t.available, t.availErr
	}
	p, err := newProber(false)
	ok := err == nil
	if p != nil {
		_ = p.Close()
	}
	t.available = &ok
	if err != nil {
		t.availErr = fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return ok, t.availErr
}

// prober is the socket mechanism used to send TTL-limited probes and read replies.
// Its implementation is platform-specific: see prober_linux.go and prober_other.go.
type prober interface {
	// SetTTL sets the hop limit for subsequent probes.
	SetTTL(ttl int) error
	// Send transmits one echo request with the given sequence number.
	Send(dst netip.Addr, seq int) error
	// Receive waits for a reply, returning the responding address, what kind of reply
	// it was, and the sequence number of the probe it refers to.
	Receive(timeout time.Duration) (addr string, kind replyKind, seq int, err error)
	// Raw reports whether a raw socket was used, which is recorded with the result.
	Raw() bool
	Close() error
}

// Trace measures the path to a destination.
func (t *Tracer) Trace(ctx context.Context, destination string) (Path, error) {
	path := Path{Destination: destination, Method: "icmp"}
	start := time.Now()

	addr, err := resolve(ctx, destination)
	if err != nil {
		return path, err
	}
	path.Resolved = addr.String()
	v6 := addr.Is6() && !addr.Is4In6()

	p, err := newProber(v6)
	if err != nil {
		return path, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer p.Close()
	if p.Raw() {
		path.Method = "icmp-raw"
	}

	traceCtx, cancel := context.WithTimeout(ctx, t.cfg.TotalTimeout)
	defer cancel()

	for ttl := 1; ttl <= t.cfg.MaxHops; ttl++ {
		if traceCtx.Err() != nil {
			break
		}
		hop, reached := t.probeHop(traceCtx, p, addr, ttl)
		path.Hops = append(path.Hops, hop)
		if reached {
			path.Complete = true
			path.RTT = hop.RTT
			break
		}
	}
	path.Duration = time.Since(start)
	if len(path.Hops) == 0 {
		return path, fmt.Errorf("routing: no hop responded for %s", destination)
	}
	return path, nil
}

// probeHop sends probes for one TTL and returns what answered.
func (t *Tracer) probeHop(ctx context.Context, p prober, target netip.Addr, ttl int) (Hop, bool) {
	hop := Hop{TTL: ttl, Timeout: true}

	for probe := 0; probe < t.cfg.ProbesPerHop; probe++ {
		if ctx.Err() != nil {
			break
		}
		if err := p.SetTTL(ttl); err != nil {
			return hop, false
		}
		seq := nextSeq()
		sent := time.Now()
		if err := p.Send(target, seq); err != nil {
			continue
		}

		timeout := t.cfg.Timeout
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining < timeout {
				timeout = remaining
			}
		}
		if timeout <= 0 {
			break
		}

		// Read until the reply to this probe arrives or the timeout expires: the socket
		// also sees replies to other probes and unrelated ICMP traffic.
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			addr, kind, replySeq, err := p.Receive(time.Until(deadline))
			if err != nil {
				break
			}
			if kind == replyNone {
				continue
			}
			// A datagram ping socket rewrites the identifier, so the sequence number is
			// what ties a reply to its probe.
			if replySeq != -1 && replySeq != seq {
				continue
			}
			hop.Timeout = false
			hop.Addr = addr
			hop.RTT = time.Since(sent)
			if kind == replyEcho || addr == target.String() {
				hop.Destination = true
				return hop, true
			}
			return hop, false
		}
	}
	return hop, false
}

type replyKind int

const (
	replyNone replyKind = iota
	// replyTimeExceeded is an intermediate hop reporting the TTL expired.
	replyTimeExceeded
	// replyEcho is the destination answering.
	replyEcho
	// replyUnreachable is a hop reporting the destination cannot be reached.
	replyUnreachable
)

// classify identifies a received ICMP message and extracts the sequence number of the
// probe it refers to.
// embeddedSeq extracts the sequence number from the original datagram quoted inside an
// ICMP error message.
func embeddedSeq(data []byte, v6 bool) int {
	// The quoted payload begins with the original IP header.
	headerLen := 20
	if v6 {
		headerLen = 40
	} else if len(data) > 0 {
		headerLen = int(data[0]&0x0f) * 4
		if headerLen < 20 {
			headerLen = 20
		}
	}
	if len(data) < headerLen+8 {
		return -1
	}
	inner := data[headerLen:]
	// ICMP header: type, code, checksum, id, seq.
	if len(inner) < 8 {
		return -1
	}
	return int(inner[6])<<8 | int(inner[7])
}

func resolve(ctx context.Context, destination string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(destination); err == nil {
		return addr, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("routing: resolve %s: %w", destination, err)
	}
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return netip.Addr{}, fmt.Errorf("routing: no address for %s", destination)
}

// addrOf renders a peer address; used by the portable prober.
func addrOf(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	return ""
}

var seqCounter struct {
	sync.Mutex
	n int
}

func nextSeq() int {
	seqCounter.Lock()
	defer seqCounter.Unlock()
	// Start above the latency prober's range so the two cannot be confused when they
	// share a socket type.
	seqCounter.n = (seqCounter.n + 1) & 0x7fff
	return seqCounter.n | 0x4000
}

// Compare reports how two paths differ, which is what decides whether a change is worth
// reporting. ECMP causes benign hop variation, so a tolerance is applied.
type Diff struct {
	Changed bool
	// HopCountDelta is the change in hop count.
	HopCountDelta int
	// ChangedHops counts positions where the responding address differs.
	ChangedHops int
	// FirstChange is the first hop number that differs.
	FirstChange int
}

// Compare computes the difference between two paths.
func Compare(before, after Path, tolerance int) Diff {
	d := Diff{HopCountDelta: after.HopCount() - before.HopCount()}
	max := len(before.Hops)
	if len(after.Hops) > max {
		max = len(after.Hops)
	}
	for i := 0; i < max; i++ {
		var b, a string
		if i < len(before.Hops) {
			b = before.Hops[i].Addr
		}
		if i < len(after.Hops) {
			a = after.Hops[i].Addr
		}
		// A hop that stopped or started answering is not a route change: intermediate
		// routers rate-limit ICMP, so this happens constantly on a stable path.
		if b == "" || a == "" {
			continue
		}
		if b != a {
			d.ChangedHops++
			if d.FirstChange == 0 {
				d.FirstChange = i + 1
			}
		}
	}
	if tolerance < 0 {
		tolerance = 0
	}
	d.Changed = d.ChangedHops > tolerance
	return d
}
