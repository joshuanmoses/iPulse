// Package network turns the platform's raw socket tables into normalised connection
// records: internal or external, with the owning process where the platform allows it.
//
// Only metadata is handled here. There is no packet capture, no payload inspection and
// no TLS interception anywhere in iPulse, so the most this package ever knows about a
// connection is who opened it, where it went, and how long it lasted.
package network

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/util"
)

// Privacy controls which optional identity fields are recorded. Every field here is a
// deliberate choice an operator can turn off.
type Privacy struct {
	CollectProcessNames    bool
	CollectExecutablePaths bool
	CollectUsernames       bool
	AnonymizeLocal         bool
}

// Config configures the collector.
type Config struct {
	IncludeUDP       bool
	IncludeListening bool
	IncludeLoopback  bool
	ResolveProcess   bool
	Max              int
	// InternalRanges are site-specific ranges that count as internal.
	InternalRanges []netip.Prefix
	// IgnoreProcesses skips connections owned by these processes (glob patterns).
	IgnoreProcesses []string
	// IgnoreDestinations skips these destination prefixes.
	IgnoreDestinations []netip.Prefix
	Privacy            Privacy
}

// Snapshot is one collection cycle.
type Snapshot struct {
	Time        time.Time
	Connections []database.Connection
	// Counts by category, for the summary metrics.
	Total     int
	External  int
	Internal  int
	Listening int
	TCP       int
	UDP       int
	// Failed counts connections in a failing state (SYN_SENT with no reply), which is
	// the signal a scan detector needs.
	Failed int
	// WithProcess counts how many were attributed to a process, so degraded attribution
	// is visible rather than silent.
	WithProcess int
	// Skipped counts rows dropped by the ignore rules.
	Skipped int
}

// Collector normalises platform connections.
type Collector struct {
	cfg  Config
	plat platform.Provider
	// firstSeen remembers when a connection was first observed, so a duration can be
	// reported without asking the kernel for something it does not track.
	firstSeen map[string]time.Time
}

// NewCollector creates a collector.
func NewCollector(cfg Config, plat platform.Provider) *Collector {
	return &Collector{cfg: cfg, plat: plat, firstSeen: map[string]time.Time{}}
}

// Collect reads the socket tables and returns normalised records.
func (c *Collector) Collect(now time.Time) (Snapshot, error) {
	raw, err := c.plat.Connections(platform.ConnOptions{
		TCP:              true,
		UDP:              c.cfg.IncludeUDP,
		IncludeListening: c.cfg.IncludeListening,
		IncludeLoopback:  c.cfg.IncludeLoopback,
		ResolveProcess:   c.cfg.ResolveProcess,
		Max:              c.cfg.Max,
	})
	if err != nil {
		return Snapshot{Time: now}, err
	}

	snap := Snapshot{Time: now, Connections: make([]database.Connection, 0, len(raw))}
	live := make(map[string]bool, len(raw))

	for _, r := range raw {
		if c.ignore(r) {
			snap.Skipped++
			continue
		}
		key := platform.ConnectionKey(r)
		live[key] = true

		first, seen := c.firstSeen[key]
		if !seen {
			first = now
			c.firstSeen[key] = first
		}

		internal := util.IsInternal(r.Remote.Addr(), c.cfg.InternalRanges)
		conn := database.Connection{
			Key:        key,
			FirstSeen:  first,
			LastSeen:   now,
			Protocol:   r.Protocol,
			LocalIP:    c.localAddr(r.Local.Addr()),
			LocalPort:  int(r.Local.Port()),
			RemoteIP:   r.Remote.Addr().String(),
			RemotePort: int(r.Remote.Port()),
			State:      r.State,
			Duration:   now.Sub(first),
			Internal:   internal,
		}
		if !r.Remote.Addr().IsValid() {
			conn.RemoteIP = ""
		}
		if c.cfg.Privacy.CollectProcessNames {
			conn.PID = r.PID
			conn.Process = r.Process
		}
		if c.cfg.Privacy.CollectExecutablePaths {
			conn.Exe = r.Exe
		}
		if c.cfg.Privacy.CollectUsernames {
			conn.User = r.User
		}
		// Kernel socket queue depths are the only byte-ish counters either platform
		// exposes per socket without packet capture. They are queue depths, not
		// totals, so they are recorded as a coarse activity indicator only.
		conn.BytesSent = int64(r.TxQueue)
		conn.BytesRecv = int64(r.RxQueue)

		snap.Connections = append(snap.Connections, conn)
		snap.Total++
		switch {
		case r.State == platform.StateListen:
			snap.Listening++
		case internal:
			snap.Internal++
		default:
			snap.External++
		}
		if r.Protocol == "udp" {
			snap.UDP++
		} else {
			snap.TCP++
		}
		if isFailing(r.State) {
			snap.Failed++
		}
		if conn.Process != "" {
			snap.WithProcess++
		}
	}

	// Forget connections that have gone, bounding memory on a busy host.
	for key := range c.firstSeen {
		if !live[key] {
			delete(c.firstSeen, key)
		}
	}
	return snap, nil
}

// isFailing reports whether a state indicates an attempt that is not succeeding, which
// is what distinguishes a scan from normal traffic.
func isFailing(state string) bool {
	return state == platform.StateSynSent || state == platform.StateClosed
}

func (c *Collector) ignore(r platform.Connection) bool {
	if len(c.cfg.IgnoreProcesses) > 0 && r.Process != "" &&
		util.MatchesAnyGlob(c.cfg.IgnoreProcesses, r.Process) {
		return true
	}
	if len(c.cfg.IgnoreDestinations) > 0 && r.Remote.Addr().IsValid() &&
		util.MatchesAnyPrefix(r.Remote.Addr(), c.cfg.IgnoreDestinations) {
		return true
	}
	return false
}

// localAddr optionally masks the host portion of a local address. Some sites consider a
// workstation's own address identifying information.
func (c *Collector) localAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if !c.cfg.Privacy.AnonymizeLocal {
		return addr.String()
	}
	if addr.Is4() {
		b := addr.As4()
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], 0}).String() + "/24"
	}
	p := netip.PrefixFrom(addr, 64).Masked()
	return p.String()
}

// ProcessSummary aggregates a snapshot by process, which is what the traffic and
// destination reporting needs when naming a responsible application.
type ProcessSummary struct {
	Process      string
	PID          int
	Connections  int
	External     int
	Internal     int
	Failed       int
	Destinations map[string]bool
}

// SummariseByProcess groups a snapshot by process name.
func SummariseByProcess(snap Snapshot) []ProcessSummary {
	byName := map[string]*ProcessSummary{}
	for _, c := range snap.Connections {
		name := c.Process
		if name == "" {
			name = "(unattributed)"
		}
		s, ok := byName[name]
		if !ok {
			s = &ProcessSummary{Process: name, PID: c.PID, Destinations: map[string]bool{}}
			byName[name] = s
		}
		s.Connections++
		if c.Internal {
			s.Internal++
		} else {
			s.External++
		}
		if isFailing(c.State) {
			s.Failed++
		}
		if c.RemoteIP != "" {
			s.Destinations[c.RemoteIP] = true
		}
	}
	out := make([]ProcessSummary, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		return out[i].Process < out[j].Process
	})
	return out
}

// TopProcess names the process with the most connections, for event fields.
func TopProcess(snap Snapshot) string {
	summaries := SummariseByProcess(snap)
	for _, s := range summaries {
		if s.Process != "(unattributed)" {
			return s.Process
		}
	}
	if len(summaries) > 0 {
		return summaries[0].Process
	}
	return ""
}

// DistinctExternalDestinations counts unique external remote addresses.
func DistinctExternalDestinations(snap Snapshot) int {
	seen := map[string]bool{}
	for _, c := range snap.Connections {
		if c.Internal || c.RemoteIP == "" {
			continue
		}
		seen[c.RemoteIP] = true
	}
	return len(seen)
}

// EndpointKey is the identity of a destination: address, port and protocol.
func EndpointKey(ip string, port int, proto string) string {
	return strings.ToLower(proto) + "|" + ip + "|" + itoa(port)
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
