package platform

import (
	"net/netip"
	"testing"
)

func TestClassifyInterface(t *testing.T) {
	cases := []struct {
		name                             string
		loopback, pointToPoint, wireless bool
		want                             string
	}{
		{"lo", true, false, false, IfaceLoopback},
		{"eth0", false, false, false, IfaceEthernet},
		{"enp3s0", false, false, false, IfaceEthernet},
		{"wlan0", false, false, true, IfaceWireless},
		{"wlp2s0", false, false, false, IfaceWireless},
		{"tun0", false, true, false, IfaceTunnel},
		{"wg0", false, false, false, IfaceTunnel},
		{"nordlynx", false, false, false, IfaceTunnel},
		{"docker0", false, false, false, IfaceVirtual},
		{"br-abc123", false, false, false, IfaceVirtual},
		{"veth9f1", false, false, false, IfaceVirtual},
		{"Ethernet", false, false, false, IfaceEthernet},
		{"Wi-Fi", false, false, false, IfaceWireless},
	}
	for _, c := range cases {
		if got := ClassifyInterface(c.name, c.loopback, c.pointToPoint, c.wireless); got != c.want {
			t.Errorf("ClassifyInterface(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsTunnelIdentifiesVPNs(t *testing.T) {
	for _, name := range []string{"tun0", "wg0", "utun3", "tailscale0", "ipsec0", "ppp0"} {
		if !IsTunnel(name) {
			t.Errorf("IsTunnel(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"eth0", "wlan0", "lo", "docker0"} {
		if IsTunnel(name) {
			t.Errorf("IsTunnel(%q) = true, want false", name)
		}
	}
}

func TestDefaultRouteSelection(t *testing.T) {
	routes := []Route{
		{Destination: netip.MustParsePrefix("192.168.1.0/24"), Interface: "eth0", Metric: 100},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"),
			Interface: "eth0", Metric: 600, Default: true},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.8.0.1"),
			Interface: "tun0", Metric: 50, Default: true},
		{Destination: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"),
			Interface: "eth0", Metric: 20, Default: true},
	}
	best, ok := DefaultRoute(routes)
	if !ok {
		t.Fatal("expected a default route")
	}
	// Lowest metric wins overall.
	if best.Interface != "eth0" || !best.Destination.Addr().Is6() {
		t.Errorf("expected the lowest-metric default (IPv6 via eth0), got %+v", best)
	}
	v4, ok := DefaultRouteFor(routes, true)
	if !ok || v4.Interface != "tun0" {
		t.Errorf("expected the VPN default for IPv4, got %+v ok=%v", v4, ok)
	}
	if _, ok := DefaultRoute(routes[:1]); ok {
		t.Error("a table with no default route must report none")
	}
}

func TestSignalPercent(t *testing.T) {
	cases := map[int]int{-30: 100, -50: 100, -60: 80, -70: 60, -75: 50, -100: 0, -120: 0}
	for dbm, want := range cases {
		if got := SignalPercent(dbm); got != want {
			t.Errorf("SignalPercent(%d) = %d, want %d", dbm, got, want)
		}
	}
}

func TestChannelAndBandMapping(t *testing.T) {
	cases := []struct {
		mhz  int
		ch   int
		band string
	}{
		{2412, 1, "2.4GHz"},
		{2437, 6, "2.4GHz"},
		{2484, 14, "2.4GHz"},
		{5180, 36, "5GHz"},
		{5500, 100, "5GHz"},
		{6135, 37, "6GHz"},
	}
	for _, c := range cases {
		if got := ChannelForFrequency(c.mhz); got != c.ch {
			t.Errorf("ChannelForFrequency(%d) = %d, want %d", c.mhz, got, c.ch)
		}
		if got := BandForFrequency(c.mhz); got != c.band {
			t.Errorf("BandForFrequency(%d) = %q, want %q", c.mhz, got, c.band)
		}
	}
}

func TestInterfacePrimaryAddrPrefersIPv4(t *testing.T) {
	i := Interface{Addrs: []netip.Prefix{
		netip.MustParsePrefix("fe80::1/64"),      // link-local: skipped
		netip.MustParsePrefix("2001:db8::5/64"),  // global v6
		netip.MustParsePrefix("192.168.1.20/24"), // global v4, preferred
	}}
	addr, ok := i.PrimaryAddr()
	if !ok || addr.String() != "192.168.1.20" {
		t.Errorf("PrimaryAddr = %v ok=%v, want 192.168.1.20", addr, ok)
	}

	v6Only := Interface{Addrs: []netip.Prefix{
		netip.MustParsePrefix("fe80::1/64"),
		netip.MustParsePrefix("2001:db8::5/64"),
	}}
	addr, ok = v6Only.PrimaryAddr()
	if !ok || addr.String() != "2001:db8::5" {
		t.Errorf("PrimaryAddr = %v ok=%v, want 2001:db8::5", addr, ok)
	}

	if _, ok := (Interface{}).PrimaryAddr(); ok {
		t.Error("an interface with no addresses must report none")
	}
}

func TestConnectionKeyIsStable(t *testing.T) {
	c := Connection{
		Protocol: "tcp",
		Local:    netip.MustParseAddrPort("10.0.0.5:5000"),
		Remote:   netip.MustParseAddrPort("203.0.113.7:443"),
		PID:      900,
	}
	k1 := ConnectionKey(c)
	c.State = StateEstablished // state changes must not change identity
	if k2 := ConnectionKey(c); k1 != k2 {
		t.Errorf("key changed with state: %q vs %q", k1, k2)
	}
	c.PID = 901
	if k3 := ConnectionKey(c); k1 == k3 {
		t.Error("different processes must produce different keys")
	}
}

// TestLiveProviderIsSane exercises the real provider for this platform. It asserts only
// what must hold on any host, so it is safe in CI containers.
func TestLiveProviderIsSane(t *testing.T) {
	p := New()
	if p.Name() == "" {
		t.Error("provider must report a name")
	}
	caps := p.Capabilities()
	if caps.Platform == "" {
		t.Error("capabilities must report a platform")
	}

	ifaces, err := p.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("expected at least the loopback interface")
	}
	var sawLoopback bool
	for _, i := range ifaces {
		if i.Name == "" {
			t.Error("interface with no name")
		}
		if i.IsLoopback() {
			sawLoopback = true
		}
	}
	if !sawLoopback {
		t.Error("expected to find a loopback interface")
	}
	t.Logf("provider=%s elevated=%v icmp=%v wireless=%v interfaces=%d limitations=%v",
		p.Name(), caps.Elevated, caps.ICMP, caps.Wireless, len(ifaces), caps.Limitations())
}
