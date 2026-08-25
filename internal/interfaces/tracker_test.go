package interfaces

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/platform"
)

func iface(name, typ string, up, running bool, addrs ...string) platform.Interface {
	i := platform.Interface{Name: name, Type: typ, Up: up, Running: running, MTU: 1500}
	for _, a := range addrs {
		i.Addrs = append(i.Addrs, netip.MustParsePrefix(a))
	}
	return i
}

func snapshot(t time.Time, ifaces []platform.Interface, gw string, gwIface string) Snapshot {
	s := Snapshot{Time: t, Interfaces: ifaces}
	if gwIface != "" {
		route := platform.Route{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Interface:   gwIface,
			Default:     true,
		}
		if gw != "" {
			route.Gateway = netip.MustParseAddr(gw)
		}
		s.Routes = []platform.Route{route}
		s.DefaultRoute = &s.Routes[0]
		s.VPNActive = platform.IsTunnel(gwIface)
		for i := range s.Interfaces {
			if s.Interfaces[i].Name == gwIface {
				s.DefaultIface = &s.Interfaces[i]
			}
		}
	}
	return s
}

func kinds(changes []Change) map[ChangeKind]Change {
	out := map[ChangeKind]Change{}
	for _, c := range changes {
		out[c.Kind] = c
	}
	return out
}

// TestFirstObservationIsSilent matters because an agent restart must not log a change
// for every interface that already exists.
func TestFirstObservationIsSilent(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	changes := tr.Observe(snapshot(now,
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")},
		"192.168.1.1", "eth0"))
	if len(changes) != 0 {
		t.Errorf("first observation produced %d changes: %+v", len(changes), changes)
	}
}

func TestInterfaceDownAndUp(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	tr.Observe(snapshot(now,
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")},
		"192.168.1.1", "eth0"))

	// The cable is unplugged: still administratively up, but no carrier and no route.
	changes := tr.Observe(snapshot(now.Add(30*time.Second),
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, false, "192.168.1.20/24")},
		"", ""))
	byKind := kinds(changes)
	if _, ok := byKind[InterfaceDown]; !ok {
		t.Errorf("carrier loss should report the interface as down: %+v", changes)
	}
	if _, ok := byKind[DefaultIfaceChange]; !ok {
		t.Errorf("losing the default route should be reported: %+v", changes)
	}

	// Plugged back in.
	changes = tr.Observe(snapshot(now.Add(60*time.Second),
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")},
		"192.168.1.1", "eth0"))
	byKind = kinds(changes)
	if _, ok := byKind[DefaultIfaceChange]; !ok {
		t.Errorf("regaining the default route should be reported: %+v", changes)
	}
}

func TestAddressChange(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	tr.Observe(snapshot(now,
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")},
		"192.168.1.1", "eth0"))
	changes := tr.Observe(snapshot(now.Add(time.Minute),
		[]platform.Interface{iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.55/24")},
		"192.168.1.1", "eth0"))

	c, ok := kinds(changes)[AddressesChanged]
	if !ok {
		t.Fatalf("address change not reported: %+v", changes)
	}
	if c.Previous != "192.168.1.20/24" || c.Current != "192.168.1.55/24" {
		t.Errorf("change reported %q -> %q", c.Previous, c.Current)
	}
}

// TestVPNActivation is the scenario the requirements call out: a tunnel takes over the
// default route, and the public IP and resolvers change with it.
func TestVPNActivation(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	eth := iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")
	tun := iface("tun0", platform.IfaceTunnel, true, true, "10.8.0.2/32")

	before := snapshot(now, []platform.Interface{eth}, "192.168.1.1", "eth0")
	before.DNSServers = []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")}
	tr.Observe(before)

	after := snapshot(now.Add(30*time.Second), []platform.Interface{eth, tun}, "10.8.0.1", "tun0")
	after.DNSServers = []netip.AddrPort{netip.MustParseAddrPort("10.8.0.1:53")}
	changes := tr.Observe(after)

	byKind := kinds(changes)
	for _, want := range []ChangeKind{DefaultIfaceChange, GatewayChanged, VPNStateChanged, DNSServersChanged, InterfaceUp} {
		if _, ok := byKind[want]; !ok {
			t.Errorf("VPN activation did not report %s: %+v", want, changes)
		}
	}
	if c := byKind[VPNStateChanged]; c.Current != "true" {
		t.Errorf("VPN state reported as %q", c.Current)
	}
	if c := byKind[GatewayChanged]; c.Previous != "192.168.1.1" || c.Current != "10.8.0.1" {
		t.Errorf("gateway change reported %q -> %q", c.Previous, c.Current)
	}
}

func TestWirelessRoaming(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	wl := iface("wlan0", platform.IfaceWireless, true, true, "192.168.1.30/24")

	before := snapshot(now, []platform.Interface{wl}, "192.168.1.1", "wlan0")
	before.Wireless = []platform.WirelessLink{{
		Interface: "wlan0", SSID: "Home", BSSID: "aa:bb:cc:dd:ee:01", SignalDBM: -52, LinkMbps: 866,
	}}
	tr.Observe(before)

	// Roamed to a different access point on the same network.
	after := snapshot(now.Add(time.Minute), []platform.Interface{wl}, "192.168.1.1", "wlan0")
	after.Wireless = []platform.WirelessLink{{
		Interface: "wlan0", SSID: "Home", BSSID: "aa:bb:cc:dd:ee:02", SignalDBM: -61, LinkMbps: 585,
	}}
	changes := tr.Observe(after)
	if _, ok := kinds(changes)[WiFiNetworkChanged]; !ok {
		t.Errorf("roaming to a new BSSID should be reported: %+v", changes)
	}

	// Association lost.
	gone := snapshot(now.Add(2*time.Minute), []platform.Interface{wl}, "192.168.1.1", "wlan0")
	changes = tr.Observe(gone)
	if _, ok := kinds(changes)[WiFiDisconnected]; !ok {
		t.Errorf("losing the association should be reported: %+v", changes)
	}
}

func TestErrorRateReporting(t *testing.T) {
	tr := NewTracker(5) // 5 errors per second
	now := time.Now()

	before := iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")
	tr.Observe(snapshot(now, []platform.Interface{before}, "192.168.1.1", "eth0"))

	// 300 new errors over 30 seconds is 10/s, above the threshold.
	after := before
	after.Counters.RxErrors = 200
	after.Counters.TxDropped = 100
	changes := tr.Observe(snapshot(now.Add(30*time.Second), []platform.Interface{after}, "192.168.1.1", "eth0"))
	if _, ok := kinds(changes)[ErrorsRising]; !ok {
		t.Errorf("expected an error-rate change: %+v", changes)
	}

	// A small increase stays below the threshold.
	after2 := after
	after2.Counters.RxErrors = 210
	changes = tr.Observe(snapshot(now.Add(60*time.Second), []platform.Interface{after2}, "192.168.1.1", "eth0"))
	if _, ok := kinds(changes)[ErrorsRising]; ok {
		t.Errorf("10 errors over 30s is below the threshold: %+v", changes)
	}
}

func TestLoopbackIsIgnored(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	lo := iface("lo", platform.IfaceLoopback, true, true, "127.0.0.1/8")
	eth := iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")
	tr.Observe(snapshot(now, []platform.Interface{lo, eth}, "192.168.1.1", "eth0"))

	// Loopback disappearing (which cannot really happen) must produce no noise.
	changes := tr.Observe(snapshot(now.Add(time.Minute), []platform.Interface{eth}, "192.168.1.1", "eth0"))
	if len(changes) != 0 {
		t.Errorf("loopback changes should be ignored: %+v", changes)
	}
}

func TestLinkSpeedChange(t *testing.T) {
	tr := NewTracker(0)
	now := time.Now()
	fast := iface("eth0", platform.IfaceEthernet, true, true, "192.168.1.20/24")
	fast.SpeedMbps = 1000
	tr.Observe(snapshot(now, []platform.Interface{fast}, "192.168.1.1", "eth0"))

	slow := fast
	slow.SpeedMbps = 100
	changes := tr.Observe(snapshot(now.Add(time.Minute), []platform.Interface{slow}, "192.168.1.1", "eth0"))
	c, ok := kinds(changes)[LinkSpeedChanged]
	if !ok {
		t.Fatalf("link speed change not reported: %+v", changes)
	}
	if c.Previous != "1Gbps" || c.Current != "100Mbps" {
		t.Errorf("speed change reported %q -> %q", c.Previous, c.Current)
	}
}

func TestCollectFromLiveProvider(t *testing.T) {
	snap, err := Collect(platform.New())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(snap.Interfaces) == 0 {
		t.Error("expected at least one interface")
	}
	if snap.Time.IsZero() {
		t.Error("snapshot has no timestamp")
	}
}
