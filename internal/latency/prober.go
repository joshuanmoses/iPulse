// Package latency measures round-trip time, jitter and packet loss.
//
// Two mechanisms are available. ICMP echo is the accurate one and is used whenever the
// process may open an ICMP socket. Where it may not - an unprivileged Windows service,
// or a Linux host with a restrictive ping_group_range and no CAP_NET_RAW - the prober
// falls back to timing TCP handshakes, and says so in every result it produces. A
// measurement whose method is unclear is worse than no measurement, so the method is
// always recorded alongside the numbers.
package latency

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// Method selects the measurement mechanism.
type Method string

// Measurement methods.
const (
	// MethodAuto prefers ICMP and falls back to TCP.
	MethodAuto Method = "auto"
	MethodICMP Method = "icmp"
	MethodTCP  Method = "tcp"
)

// Result is one target's measurement for one cycle.
type Result struct {
	Target string          `json:"target"`
	Method Method          `json:"method"`
	Sent   int             `json:"sent"`
	Recv   int             `json:"received"`
	RTTs   []time.Duration `json:"-"`

	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Avg    time.Duration `json:"avg"`
	Median time.Duration `json:"median"`
	// Jitter is the mean absolute difference between consecutive round trips, which is
	// what matters for real-time traffic and is comparable across tools.
	Jitter  time.Duration `json:"jitter"`
	LossPct float64       `json:"loss_percent"`
	// Err is set when no probe succeeded at all.
	Err error `json:"-"`
	// Error carries the failure text for JSON consumers.
	Error string `json:"error,omitempty"`
	// Resolved is the address actually probed, which differs from Target for names.
	Resolved string `json:"resolved,omitempty"`
}

// OK reports whether at least one probe was answered.
func (r Result) OK() bool { return r.Recv > 0 }

// AvgMS returns the mean round trip in milliseconds.
func (r Result) AvgMS() float64 { return float64(r.Avg) / float64(time.Millisecond) }

// JitterMS returns jitter in milliseconds.
func (r Result) JitterMS() float64 { return float64(r.Jitter) / float64(time.Millisecond) }

// Config configures a prober.
type Config struct {
	Method  Method
	Probes  int
	Spacing time.Duration
	Timeout time.Duration
	// TCPPort is the port used by the TCP method.
	TCPPort int
}

// Prober measures latency to targets.
type Prober struct {
	cfg Config
	// icmpUsable caches whether ICMP sockets can be opened, so a host without the
	// privilege does not retry (and log) on every cycle.
	icmpUsable  bool
	icmpChecked bool
	icmpErr     error

	// icmpBlocked remembers targets that answer TCP but not ICMP, so a firewalled
	// target is not probed twice on every cycle. The memo expires so a temporary
	// filtering change is picked up again.
	mu          sync.Mutex
	icmpBlocked map[string]time.Time
}

// icmpBlockedTTL is how long a target stays marked as ICMP-filtered.
const icmpBlockedTTL = 15 * time.Minute

// New creates a prober, applying defaults for unset values.
func New(cfg Config) *Prober {
	if cfg.Probes <= 0 {
		cfg.Probes = 5
	}
	if cfg.Spacing <= 0 {
		cfg.Spacing = 200 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.TCPPort <= 0 {
		cfg.TCPPort = 443
	}
	if cfg.Method == "" {
		cfg.Method = MethodAuto
	}
	return &Prober{cfg: cfg, icmpBlocked: map[string]time.Time{}}
}

// Method reports the mechanism the prober will actually use.
func (p *Prober) Method() Method {
	switch p.cfg.Method {
	case MethodICMP:
		return MethodICMP
	case MethodTCP:
		return MethodTCP
	default:
		if p.icmpAvailable() {
			return MethodICMP
		}
		return MethodTCP
	}
}

// ICMPError returns why ICMP is unavailable, when it is.
func (p *Prober) ICMPError() error {
	p.icmpAvailable()
	return p.icmpErr
}

func (p *Prober) icmpAvailable() bool {
	if !p.icmpChecked {
		p.icmpChecked = true
		p.icmpUsable, p.icmpErr = probeICMPSupport()
	}
	return p.icmpUsable
}

// Probe measures one target.
func (p *Prober) Probe(ctx context.Context, target string) Result {
	method := p.Method()
	if p.cfg.Method == MethodICMP && !p.icmpAvailable() {
		return Result{
			Target: target, Method: MethodICMP,
			Err:   fmt.Errorf("icmp is not available: %w", p.icmpErr),
			Error: fmt.Sprintf("icmp is not available: %v", p.icmpErr),
		}
	}

	if method == MethodICMP && p.cfg.Method == MethodAuto && p.icmpFiltered(target) {
		method = MethodTCP
	}

	var res Result
	switch method {
	case MethodICMP:
		res = p.probeICMP(ctx, target)
		// A target that never answers ICMP (a firewall dropping echo) still tells us
		// something useful over TCP, so fall back rather than reporting 100 % loss.
		if res.Recv == 0 && p.cfg.Method == MethodAuto {
			tcpRes := p.probeTCP(ctx, target)
			if tcpRes.Recv > 0 {
				p.markICMPFiltered(target)
				return tcpRes
			}
		}
	default:
		res = p.probeTCP(ctx, target)
	}
	return res
}

// icmpFiltered reports whether this target is currently marked ICMP-filtered.
func (p *Prober) icmpFiltered(target string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.icmpBlocked[target]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(p.icmpBlocked, target)
		return false
	}
	return true
}

func (p *Prober) markICMPFiltered(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.icmpBlocked[target] = time.Now().Add(icmpBlockedTTL)
}

// ProbeAll measures every target sequentially. Sequential probing keeps the traffic
// iPulse generates negligible and avoids the targets interfering with each other.
func (p *Prober) ProbeAll(ctx context.Context, targets []string) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		out = append(out, p.Probe(ctx, t))
	}
	return out
}

// summarise fills the statistics of a result from its round-trip samples.
func summarise(res *Result) {
	res.LossPct = 0
	if res.Sent > 0 {
		res.LossPct = float64(res.Sent-res.Recv) / float64(res.Sent) * 100
	}
	if len(res.RTTs) == 0 {
		if res.Err != nil {
			res.Error = res.Err.Error()
		}
		return
	}
	sorted := make([]time.Duration, len(res.RTTs))
	copy(sorted, res.RTTs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	res.Min, res.Max = sorted[0], sorted[len(sorted)-1]
	var total time.Duration
	for _, d := range res.RTTs {
		total += d
	}
	res.Avg = total / time.Duration(len(res.RTTs))
	res.Median = sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		res.Median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	res.Jitter = meanDeviation(res.RTTs)
	if res.Err != nil {
		res.Error = res.Err.Error()
	}
}

// meanDeviation is the mean absolute difference between consecutive samples.
func meanDeviation(rtts []time.Duration) time.Duration {
	if len(rtts) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(rtts); i++ {
		total += math.Abs(float64(rtts[i] - rtts[i-1]))
	}
	return time.Duration(total / float64(len(rtts)-1))
}

// Aggregate combines several target results into one connection-level view. The best
// (lowest-latency) responding target represents the connection, because a single slow
// or rate-limiting target should not be read as a degraded Internet connection.
type Aggregate struct {
	Method    Method        `json:"method"`
	Targets   int           `json:"targets"`
	Responded int           `json:"responded"`
	Avg       time.Duration `json:"avg"`
	Best      time.Duration `json:"best"`
	Jitter    time.Duration `json:"jitter"`
	LossPct   float64       `json:"loss_percent"`
	Results   []Result      `json:"results"`
}

// Aggregate summarises per-target results.
func Aggregate_(results []Result) Aggregate {
	agg := Aggregate{Targets: len(results), Results: results, Best: -1}
	var (
		sumRTT    time.Duration
		sumJitter time.Duration
		sent, rcv int
	)
	for _, r := range results {
		if r.Method != "" {
			agg.Method = r.Method
		}
		sent += r.Sent
		rcv += r.Recv
		if !r.OK() {
			continue
		}
		agg.Responded++
		sumRTT += r.Avg
		sumJitter += r.Jitter
		if agg.Best < 0 || r.Min < agg.Best {
			agg.Best = r.Min
		}
	}
	if agg.Responded > 0 {
		agg.Avg = sumRTT / time.Duration(agg.Responded)
		agg.Jitter = sumJitter / time.Duration(agg.Responded)
	}
	if agg.Best < 0 {
		agg.Best = 0
	}
	if sent > 0 {
		agg.LossPct = float64(sent-rcv) / float64(sent) * 100
	}
	return agg
}

// resolveTarget resolves a hostname to a single address, preferring IPv4 so results are
// comparable over time even on dual-stack hosts.
func resolveTarget(ctx context.Context, target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0].IP, nil
	}
	return nil, fmt.Errorf("no addresses for %q", target)
}
