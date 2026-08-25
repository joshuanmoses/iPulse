// Package types holds the platform-abstraction data types.
//
// It exists as a leaf package so the OS-specific implementations in
// internal/platform/{linux,windows} and the internal/platform facade can share one set
// of types without an import cycle. Callers use the aliases re-exported by
// internal/platform rather than importing this package directly.
package types

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Sentinel errors for unavailable capabilities.
var (
	// ErrUnsupported means this platform cannot provide the data at all.
	ErrUnsupported = errors.New("platform: operation not supported on this platform")
	// ErrPermission means the data exists but this process may not read it.
	ErrPermission = errors.New("platform: insufficient privileges")
	// ErrNotFound means the specific object (interface, process) does not exist.
	ErrNotFound = errors.New("platform: not found")
)

// Interface types.
const (
	IfaceEthernet = "ethernet"
	IfaceWireless = "wireless"
	IfaceLoopback = "loopback"
	IfaceTunnel   = "tunnel"
	IfaceVirtual  = "virtual"
	IfaceOther    = "other"
)

// Counters are cumulative interface statistics.
type Counters struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// Interface describes one network interface.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	Type  string `json:"type"`
	MAC   string `json:"mac,omitempty"`
	MTU   int    `json:"mtu,omitempty"`
	// Up is the administrative state; Running additionally requires carrier.
	Up      bool `json:"up"`
	Running bool `json:"running"`
	// SpeedMbps is the negotiated link rate where the platform reports it.
	SpeedMbps int            `json:"speed_mbps,omitempty"`
	Addrs     []netip.Prefix `json:"addresses,omitempty"`
	Counters  Counters       `json:"counters"`
	// Description is the human-facing adapter name (Windows) or empty (Linux).
	Description string `json:"description,omitempty"`
}

// IsLoopback reports whether this is the loopback interface.
func (i Interface) IsLoopback() bool { return i.Type == IfaceLoopback }

// IsVirtual reports whether the interface is a bridge, container or virtual device
// whose counters would double-count real traffic.
func (i Interface) IsVirtual() bool { return i.Type == IfaceVirtual }

// PrimaryAddr returns the first global unicast address, preferring IPv4 because that
// is what most diagnostics compare against.
func (i Interface) PrimaryAddr() (netip.Addr, bool) {
	var v6 netip.Addr
	for _, p := range i.Addrs {
		a := p.Addr()
		if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			continue
		}
		if a.Is4() {
			return a, true
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	if v6.IsValid() {
		return v6, true
	}
	return netip.Addr{}, false
}

// AddrStrings renders the interface addresses for storage and display.
func (i Interface) AddrStrings() []string {
	out := make([]string, 0, len(i.Addrs))
	for _, p := range i.Addrs {
		out = append(out, p.String())
	}
	return out
}

// Route is one routing-table entry.
type Route struct {
	Destination netip.Prefix `json:"destination"`
	Gateway     netip.Addr   `json:"gateway,omitempty"`
	Interface   string       `json:"interface"`
	Metric      int          `json:"metric"`
	// Default marks a default route (0.0.0.0/0 or ::/0).
	Default bool `json:"default"`
}

// Connection is one socket with its owning process, where the platform exposes it.
type Connection struct {
	Protocol string         `json:"protocol"`
	Local    netip.AddrPort `json:"local"`
	Remote   netip.AddrPort `json:"remote"`
	State    string         `json:"state"`
	PID      int            `json:"pid,omitempty"`
	Process  string         `json:"process,omitempty"`
	Exe      string         `json:"exe,omitempty"`
	User     string         `json:"user,omitempty"`
	// Inode is the Linux socket inode used for process attribution. Unused on Windows.
	Inode uint64 `json:"-"`
	// TxQueue and RxQueue are the kernel socket queue depths, the closest thing to
	// per-socket byte counters that either platform exposes without packet capture.
	TxQueue uint64 `json:"tx_queue,omitempty"`
	RxQueue uint64 `json:"rx_queue,omitempty"`
}

// Connection states, normalised across platforms.
const (
	StateEstablished = "ESTABLISHED"
	StateSynSent     = "SYN_SENT"
	StateSynRecv     = "SYN_RECV"
	StateListen      = "LISTEN"
	StateTimeWait    = "TIME_WAIT"
	StateCloseWait   = "CLOSE_WAIT"
	StateClosed      = "CLOSED"
	StateClosing     = "CLOSING"
	StateFinWait1    = "FIN_WAIT1"
	StateFinWait2    = "FIN_WAIT2"
	StateLastAck     = "LAST_ACK"
	StateDeleteTCB   = "DELETE_TCB"
	StateNone        = "NONE" // UDP has no state
)

// ConnOptions selects which sockets to collect.
type ConnOptions struct {
	TCP              bool
	UDP              bool
	IncludeListening bool
	IncludeLoopback  bool
	// ResolveProcess attributes sockets to processes. On both platforms this needs
	// elevation to see sockets owned by other users.
	ResolveProcess bool
	// Max bounds the number of returned rows on very busy hosts.
	Max int
}

// WirelessLink is wireless telemetry for one interface. Credentials are never read.
type WirelessLink struct {
	Interface    string  `json:"interface"`
	SSID         string  `json:"ssid,omitempty"`
	BSSID        string  `json:"bssid,omitempty"`
	SignalDBM    int     `json:"signal_dbm"`
	SignalPct    int     `json:"signal_percent"`
	NoiseDBM     int     `json:"noise_dbm,omitempty"`
	LinkMbps     float64 `json:"link_mbps"`
	RxMbps       float64 `json:"rx_mbps,omitempty"`
	FrequencyMHz int     `json:"frequency_mhz,omitempty"`
	Channel      int     `json:"channel,omitempty"`
	Band         string  `json:"band,omitempty"`
}

// Process identifies a running process.
type Process struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe,omitempty"`
	User string `json:"user,omitempty"`
}

// Capabilities reports which platform features are available in this process, and why
// any of them are not. `ipulse diagnostics --privileges` prints this verbatim.
type Capabilities struct {
	Platform           string            `json:"platform"`
	Elevated           bool              `json:"elevated"`
	Interfaces         bool              `json:"interfaces"`
	Routes             bool              `json:"routes"`
	Connections        bool              `json:"connections"`
	ProcessAttribution bool              `json:"process_attribution"`
	Wireless           bool              `json:"wireless"`
	ICMP               bool              `json:"icmp"`
	Traceroute         bool              `json:"traceroute"`
	DNSServers         bool              `json:"dns_servers"`
	Notes              map[string]string `json:"notes,omitempty"`
}

// Note records why a capability is unavailable, or how it is degraded.
func (c *Capabilities) Note(feature, note string) {
	if c.Notes == nil {
		c.Notes = map[string]string{}
	}
	c.Notes[feature] = note
}

// Limitations returns the notes in a stable order, for logging.
func (c Capabilities) Limitations() []string {
	out := make([]string, 0, len(c.Notes))
	for k, v := range c.Notes {
		out = append(out, k+": "+v)
	}
	sort.Strings(out)
	return out
}

// DefaultRoute returns the preferred default route: lowest metric wins, and IPv4 is
// preferred when metrics tie because most diagnostics are IPv4-first.
func DefaultRoute(routes []Route) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if !r.Default {
			continue
		}
		if !found {
			best, found = r, true
			continue
		}
		if r.Metric < best.Metric ||
			(r.Metric == best.Metric && r.Destination.Addr().Is4() && !best.Destination.Addr().Is4()) {
			best = r
		}
	}
	return best, found
}

// DefaultRouteFor returns the preferred default route for one address family.
func DefaultRouteFor(routes []Route, ipv4 bool) (Route, bool) {
	var filtered []Route
	for _, r := range routes {
		if r.Default && r.Destination.Addr().Is4() == ipv4 {
			filtered = append(filtered, r)
		}
	}
	return DefaultRoute(filtered)
}

// ClassifyInterface derives an interface type from its name and flags. Name-based
// classification is unavoidable for virtual devices, which no OS labels reliably.
func ClassifyInterface(name string, loopback, pointToPoint, wireless bool) string {
	lower := strings.ToLower(name)
	switch {
	case loopback:
		return IfaceLoopback
	case wireless:
		return IfaceWireless
	case hasAnyPrefix(lower, "tun", "tap", "wg", "ppp", "ipsec", "utun", "nordlynx", "proton", "tailscale", "zt"):
		return IfaceTunnel
	case pointToPoint:
		return IfaceTunnel
	case hasAnyPrefix(lower, "docker", "br-", "virbr", "veth", "vmnet", "vboxnet", "cni", "flannel", "kube", "lxc", "bond", "dummy"):
		return IfaceVirtual
	case hasAnyPrefix(lower, "eth", "en", "em", "eno", "ens", "enp", "ethernet"):
		return IfaceEthernet
	case hasAnyPrefix(lower, "wl", "wlan", "wifi", "wi-fi", "ath", "ra"):
		return IfaceWireless
	default:
		return IfaceOther
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// IsTunnel reports whether an interface name looks like a VPN or tunnel device, which
// the public-IP and routing monitors use to explain address and route changes.
func IsTunnel(name string) bool { return ClassifyInterface(name, false, false, false) == IfaceTunnel }

// SignalPercent converts an RSSI in dBm to the 0-100 scale operating systems display.
// The mapping is the conventional one: -50 dBm and above is full, -100 dBm is zero.
func SignalPercent(dbm int) int {
	switch {
	case dbm >= -50:
		return 100
	case dbm <= -100:
		return 0
	default:
		return 2 * (dbm + 100)
	}
}

// ChannelForFrequency converts a centre frequency in MHz to a Wi-Fi channel number.
func ChannelForFrequency(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz-2412)/5 + 1
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115: // 6 GHz (Wi-Fi 6E)
		return (mhz - 5950) / 5
	}
	return 0
}

// BandForFrequency names the Wi-Fi band for a centre frequency.
func BandForFrequency(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 4900 && mhz < 5900:
		return "5GHz"
	case mhz >= 5900 && mhz <= 7125:
		return "6GHz"
	case mhz >= 57000:
		return "60GHz"
	}
	return ""
}

// ConnectionKey builds the stable identity of a connection used for de-duplication in
// the database. The pid is included so two processes reusing the same tuple after a
// close are not merged.
func ConnectionKey(c Connection) string {
	return fmt.Sprintf("%s|%s|%s|%d", c.Protocol, c.Local.String(), c.Remote.String(), c.PID)
}
