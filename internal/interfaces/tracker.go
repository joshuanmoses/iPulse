// Package interfaces tracks network interface, route, resolver and wireless state, and
// reports what changed between observations.
//
// The diffing is separated from the reporting so it can be tested exhaustively without
// a network: given two snapshots, the set of changes is fully determined.
package interfaces

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/platform"
)

// Snapshot is one observation of the host's network configuration.
type Snapshot struct {
	Time         time.Time
	Interfaces   []platform.Interface
	Routes       []platform.Route
	Wireless     []platform.WirelessLink
	DNSServers   []netip.AddrPort
	DefaultRoute *platform.Route
	DefaultIface *platform.Interface
	VPNActive    bool
}

// Collect gathers a snapshot from a platform provider. Errors are tolerated per-source:
// a host without wireless, or without permission to read routes, still produces a useful
// snapshot of what it can see.
func Collect(p platform.Provider) (Snapshot, error) {
	s := Snapshot{Time: time.Now()}

	ifaces, err := p.Interfaces()
	if err != nil {
		return s, fmt.Errorf("interfaces: %w", err)
	}
	s.Interfaces = ifaces

	if routes, err := p.Routes(); err == nil {
		s.Routes = routes
		if def, ok := platform.DefaultRoute(routes); ok {
			s.DefaultRoute = &def
			for i := range s.Interfaces {
				if s.Interfaces[i].Name == def.Interface {
					s.DefaultIface = &s.Interfaces[i]
					break
				}
			}
			s.VPNActive = platform.IsTunnel(def.Interface)
		}
	}
	if links, err := p.Wireless(); err == nil {
		s.Wireless = links
	}
	if servers, err := p.DNSServers(); err == nil {
		s.DNSServers = servers
	}
	return s, nil
}

// ChangeKind identifies what changed.
type ChangeKind string

// Change kinds.
const (
	InterfaceUp        ChangeKind = "interface-up"
	InterfaceDown      ChangeKind = "interface-down"
	AddressesChanged   ChangeKind = "addresses-changed"
	LinkSpeedChanged   ChangeKind = "link-speed-changed"
	DefaultIfaceChange ChangeKind = "default-interface-changed"
	GatewayChanged     ChangeKind = "gateway-changed"
	DNSServersChanged  ChangeKind = "dns-servers-changed"
	VPNStateChanged    ChangeKind = "vpn-state-changed"
	WiFiConnected      ChangeKind = "wifi-connected"
	WiFiDisconnected   ChangeKind = "wifi-disconnected"
	WiFiNetworkChanged ChangeKind = "wifi-network-changed"
	ErrorsRising       ChangeKind = "interface-errors-rising"
)

// Change is one observed difference.
type Change struct {
	Kind      ChangeKind
	Interface string
	Previous  string
	Current   string
	// Fields carries extra context for the event body, in a stable order.
	Fields [][2]string
}

// Tracker diffs successive snapshots.
type Tracker struct {
	prev *Snapshot
	// errorThreshold is errors+drops per second above which ErrorsRising is reported.
	errorThreshold float64
}

// NewTracker creates a tracker. errorThreshold of zero disables error-rate reporting.
func NewTracker(errorThreshold float64) *Tracker {
	return &Tracker{errorThreshold: errorThreshold}
}

// Previous returns the last observed snapshot, if any.
func (t *Tracker) Previous() *Snapshot { return t.prev }

// Observe records a snapshot and returns what changed. The first observation produces no
// changes: everything is "new" then, and reporting it would flood the log at every start.
func (t *Tracker) Observe(s Snapshot) []Change {
	prev := t.prev
	t.prev = &s
	if prev == nil {
		return nil
	}

	var changes []Change
	prevByName := indexInterfaces(prev.Interfaces)
	curByName := indexInterfaces(s.Interfaces)

	names := make([]string, 0, len(curByName))
	for name := range curByName {
		names = append(names, name)
	}
	for name := range prevByName {
		if _, ok := curByName[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		before, hadBefore := prevByName[name]
		now, hasNow := curByName[name]

		switch {
		case !hadBefore && hasNow:
			// A newly appeared interface is only interesting once it is usable.
			if now.Up {
				changes = append(changes, Change{
					Kind: InterfaceUp, Interface: name, Current: describeInterface(now),
					Fields: [][2]string{{"Type", now.Type}, {"MAC", now.MAC},
						{"Addresses", strings.Join(now.AddrStrings(), ",")},
						{"MTU", fmt.Sprint(now.MTU)}, {"LinkSpeed", speedString(now.SpeedMbps)}},
				})
			}
		case hadBefore && !hasNow:
			changes = append(changes, Change{
				Kind: InterfaceDown, Interface: name, Previous: describeInterface(before),
				Fields: [][2]string{{"Type", before.Type},
					{"PreviousAddresses", strings.Join(before.AddrStrings(), ",")},
					{"WasDefaultRoute", fmt.Sprint(isDefaultIface(prev, name))}},
			})
		default:
			changes = append(changes, diffInterface(prev, before, now, t.errorThreshold, s.Time.Sub(prev.Time))...)
		}
	}

	// Default route and gateway.
	prevGW, curGW := gatewayString(prev.DefaultRoute), gatewayString(s.DefaultRoute)
	prevIface, curIface := routeIface(prev.DefaultRoute), routeIface(s.DefaultRoute)
	if prevIface != curIface {
		changes = append(changes, Change{
			Kind: DefaultIfaceChange, Interface: curIface, Previous: prevIface, Current: curIface,
			Fields: [][2]string{
				{"PreviousType", ifaceType(prevByName, prevIface)},
				{"CurrentType", ifaceType(curByName, curIface)},
				{"VPNActive", fmt.Sprint(s.VPNActive)},
			},
		})
	}
	if prevGW != curGW {
		changes = append(changes, Change{
			Kind: GatewayChanged, Interface: curIface, Previous: prevGW, Current: curGW,
			Fields: [][2]string{
				{"PreviousInterface", prevIface}, {"NewInterface", curIface},
				{"Metric", routeMetric(s.DefaultRoute)}, {"VPNActive", fmt.Sprint(s.VPNActive)},
			},
		})
	}
	if prev.VPNActive != s.VPNActive {
		changes = append(changes, Change{
			Kind: VPNStateChanged, Interface: curIface,
			Previous: fmt.Sprint(prev.VPNActive), Current: fmt.Sprint(s.VPNActive),
			Fields: [][2]string{
				{"VPNActive", fmt.Sprint(s.VPNActive)},
				{"InterfaceType", ifaceType(curByName, curIface)},
				{"DefaultRouteVia", curGW},
				{"DNSServers", joinAddrPorts(s.DNSServers)},
			},
		})
	}

	// Resolvers.
	if before, now := joinAddrPorts(prev.DNSServers), joinAddrPorts(s.DNSServers); before != now {
		changes = append(changes, Change{
			Kind: DNSServersChanged, Interface: curIface, Previous: before, Current: now,
			Fields: [][2]string{{"VPNActive", fmt.Sprint(s.VPNActive)}},
		})
	}

	changes = append(changes, diffWireless(prev.Wireless, s.Wireless)...)
	return changes
}

func diffInterface(prev *Snapshot, before, now platform.Interface, errorThreshold float64, elapsed time.Duration) []Change {
	var changes []Change
	if !before.Up && now.Up {
		changes = append(changes, Change{
			Kind: InterfaceUp, Interface: now.Name, Current: describeInterface(now),
			Fields: [][2]string{{"Type", now.Type}, {"MAC", now.MAC},
				{"Addresses", strings.Join(now.AddrStrings(), ",")},
				{"MTU", fmt.Sprint(now.MTU)}, {"LinkSpeed", speedString(now.SpeedMbps)}},
		})
	}
	if before.Up && !now.Up {
		changes = append(changes, Change{
			Kind: InterfaceDown, Interface: now.Name, Previous: describeInterface(before),
			Fields: [][2]string{{"Type", now.Type},
				{"PreviousAddresses", strings.Join(before.AddrStrings(), ",")},
				{"WasDefaultRoute", fmt.Sprint(isDefaultIface(prev, now.Name))}},
		})
	}
	// Carrier loss on an interface that stays administratively up is the "cable
	// unplugged" case, and it is the difference between a local fault and an ISP fault.
	if before.Running && !now.Running && now.Up {
		changes = append(changes, Change{
			Kind: InterfaceDown, Interface: now.Name, Previous: "carrier",
			Fields: [][2]string{{"Type", now.Type}, {"Detail", "interface is up but carrier was lost"},
				{"WasDefaultRoute", fmt.Sprint(isDefaultIface(prev, now.Name))}},
		})
	}

	if a, b := strings.Join(before.AddrStrings(), ","), strings.Join(now.AddrStrings(), ","); a != b {
		changes = append(changes, Change{
			Kind: AddressesChanged, Interface: now.Name, Previous: a, Current: b,
			Fields: [][2]string{{"Family", addressFamilies(now)}, {"Scope", "global"}},
		})
	}
	if before.SpeedMbps != now.SpeedMbps && now.SpeedMbps > 0 && before.SpeedMbps > 0 {
		changes = append(changes, Change{
			Kind: LinkSpeedChanged, Interface: now.Name,
			Previous: speedString(before.SpeedMbps), Current: speedString(now.SpeedMbps),
		})
	}

	if errorThreshold > 0 && elapsed > 0 {
		deltaErrors := int64(now.Counters.RxErrors+now.Counters.TxErrors+now.Counters.RxDropped+now.Counters.TxDropped) -
			int64(before.Counters.RxErrors+before.Counters.TxErrors+before.Counters.RxDropped+before.Counters.TxDropped)
		if deltaErrors > 0 {
			rate := float64(deltaErrors) / elapsed.Seconds()
			if rate >= errorThreshold {
				changes = append(changes, Change{
					Kind: ErrorsRising, Interface: now.Name,
					Current: fmt.Sprintf("%.1f/s", rate),
					Fields: [][2]string{
						{"RxErrors", fmt.Sprint(now.Counters.RxErrors)},
						{"TxErrors", fmt.Sprint(now.Counters.TxErrors)},
						{"RxDropped", fmt.Sprint(now.Counters.RxDropped)},
						{"TxDropped", fmt.Sprint(now.Counters.TxDropped)},
						{"Window", elapsed.Round(time.Second).String()},
						{"ErrorRate", fmt.Sprintf("%.2f/s", rate)},
					},
				})
			}
		}
	}
	return changes
}

func diffWireless(before, now []platform.WirelessLink) []Change {
	var changes []Change
	prevByIface := map[string]platform.WirelessLink{}
	for _, l := range before {
		prevByIface[l.Interface] = l
	}
	curByIface := map[string]platform.WirelessLink{}
	for _, l := range now {
		curByIface[l.Interface] = l
	}

	names := make([]string, 0, len(curByIface)+len(prevByIface))
	for n := range curByIface {
		names = append(names, n)
	}
	for n := range prevByIface {
		if _, ok := curByIface[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		p, had := prevByIface[name]
		c, has := curByIface[name]
		switch {
		case !had && has:
			changes = append(changes, Change{
				Kind: WiFiConnected, Interface: name, Current: c.SSID,
				Fields: wifiFields(c),
			})
		case had && !has:
			changes = append(changes, Change{
				Kind: WiFiDisconnected, Interface: name, Previous: p.SSID,
				Fields: [][2]string{{"PreviousSSID", p.SSID}, {"LastSignal", fmt.Sprintf("%ddBm", p.SignalDBM)}},
			})
		case p.SSID != c.SSID || p.BSSID != c.BSSID:
			changes = append(changes, Change{
				Kind: WiFiNetworkChanged, Interface: name, Previous: p.SSID, Current: c.SSID,
				Fields: [][2]string{
					{"PreviousSSID", p.SSID}, {"CurrentSSID", c.SSID},
					{"PreviousBSSID", p.BSSID}, {"CurrentBSSID", c.BSSID},
					{"Signal", fmt.Sprintf("%ddBm", c.SignalDBM)},
				},
			})
		}
	}
	return changes
}

func wifiFields(l platform.WirelessLink) [][2]string {
	return [][2]string{
		{"SSID", l.SSID},
		{"BSSID", l.BSSID},
		{"Signal", fmt.Sprintf("%ddBm", l.SignalDBM)},
		{"SignalPercent", fmt.Sprintf("%d%%", l.SignalPct)},
		{"LinkSpeed", fmt.Sprintf("%.1fMbps", l.LinkMbps)},
		{"Frequency", fmt.Sprintf("%dMHz", l.FrequencyMHz)},
		{"Channel", fmt.Sprint(l.Channel)},
		{"Band", l.Band},
	}
}

func indexInterfaces(list []platform.Interface) map[string]platform.Interface {
	out := make(map[string]platform.Interface, len(list))
	for _, i := range list {
		// Loopback and virtual devices change constantly on container hosts and are not
		// what an Internet monitor is watching.
		if i.IsLoopback() {
			continue
		}
		out[i.Name] = i
	}
	return out
}

func describeInterface(i platform.Interface) string {
	return fmt.Sprintf("%s (%s) %s", i.Name, i.Type, strings.Join(i.AddrStrings(), ","))
}

func isDefaultIface(s *Snapshot, name string) bool {
	return s != nil && s.DefaultRoute != nil && s.DefaultRoute.Interface == name
}

func gatewayString(r *platform.Route) string {
	if r == nil || !r.Gateway.IsValid() {
		return ""
	}
	return r.Gateway.String()
}

func routeIface(r *platform.Route) string {
	if r == nil {
		return ""
	}
	return r.Interface
}

func routeMetric(r *platform.Route) string {
	if r == nil {
		return ""
	}
	return fmt.Sprint(r.Metric)
}

func ifaceType(index map[string]platform.Interface, name string) string {
	if i, ok := index[name]; ok {
		return i.Type
	}
	return ""
}

func speedString(mbps int) string {
	if mbps <= 0 {
		return "unknown"
	}
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dGbps", mbps/1000)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

func addressFamilies(i platform.Interface) string {
	var v4, v6 bool
	for _, p := range i.Addrs {
		if p.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	switch {
	case v4 && v6:
		return "ipv4+ipv6"
	case v4:
		return "ipv4"
	case v6:
		return "ipv6"
	}
	return "none"
}

func joinAddrPorts(in []netip.AddrPort) string {
	out := make([]string, 0, len(in))
	for _, ap := range in {
		out = append(out, ap.String())
	}
	return strings.Join(out, ",")
}
