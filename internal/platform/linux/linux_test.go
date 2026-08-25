//go:build linux

package linux

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// TestParseProcAddr locks the /proc/net address encoding, which is the single most
// error-prone piece of the Linux collector: IPv4 is one little-endian word, IPv6 is four.
func TestParseProcAddr(t *testing.T) {
	cases := []struct {
		in   string
		v6   bool
		want string
	}{
		{"0100007F:1F90", false, "127.0.0.1:8080"},
		{"00000000:0050", false, "0.0.0.0:80"},
		{"0200A8C0:01BB", false, "192.168.0.2:443"},
		{"0A0A0A0A:0000", false, "10.10.10.10:0"},
		// IPv6 loopback ::1 -> four LE words, the last containing 0x00000001.
		{"00000000000000000000000001000000:1F90", true, "[::1]:8080"},
		// 2001:db8::1
		{"B80D0120000000000000000001000000:01BB", true, "[2001:db8::1]:443"},
	}
	for _, c := range cases {
		got, ok := parseProcAddr(c.in, c.v6)
		if !ok {
			t.Errorf("parseProcAddr(%q, v6=%v) failed", c.in, c.v6)
			continue
		}
		if got.String() != c.want {
			t.Errorf("parseProcAddr(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	if _, ok := parseProcAddr("garbage", false); ok {
		t.Error("expected malformed input to be rejected")
	}
}

func TestRouteHexDecoding(t *testing.T) {
	addr, ok := hexLEToAddr4("0101A8C0")
	if !ok || addr.String() != "192.168.1.1" {
		t.Errorf("hexLEToAddr4 = %v ok=%v, want 192.168.1.1", addr, ok)
	}
	if bits, ok := hexLEToMaskBits("00FFFFFF"); !ok || bits != 24 {
		t.Errorf("mask /24 decoded as %d ok=%v", bits, ok)
	}
	if bits, ok := hexLEToMaskBits("00000000"); !ok || bits != 0 {
		t.Errorf("default route mask decoded as %d ok=%v", bits, ok)
	}
	if bits, ok := hexLEToMaskBits("FFFFFFFF"); !ok || bits != 32 {
		t.Errorf("host mask decoded as %d ok=%v", bits, ok)
	}
	a, ok := hexToAddr16("20010db8000000000000000000000001")
	if !ok || a.String() != "2001:db8::1" {
		t.Errorf("hexToAddr16 = %v ok=%v", a, ok)
	}
}

// TestReadRoutesV4 parses a captured /proc/net/route, including the default route and a
// VPN route with a lower metric.
func TestReadRoutesV4(t *testing.T) {
	content := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n" +
		"tun0\t00000000\t0100080A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	routes, err := readRoutesV4(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if !routes[0].Default || routes[0].Gateway.String() != "192.168.1.1" || routes[0].Metric != 600 {
		t.Errorf("default route parsed as %+v", routes[0])
	}
	if routes[1].Default {
		t.Errorf("on-link route must not be marked default: %+v", routes[1])
	}
	if routes[1].Destination.String() != "192.168.1.0/24" {
		t.Errorf("on-link prefix = %s", routes[1].Destination)
	}
	best, ok := types.DefaultRoute(routes)
	if !ok || best.Interface != "tun0" {
		t.Errorf("lowest-metric default should be tun0, got %+v", best)
	}
}

func TestParseResolvConf(t *testing.T) {
	content := `# comment
nameserver 127.0.0.53
nameserver 8.8.8.8
nameserver fe80::1%eth0
nameserver not-an-ip
nameserver 8.8.8.8
options edns0
search example.invalid
`
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := parseResolvConf(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.53:53", "8.8.8.8:53", "[fe80::1]:53"}
	if len(servers) != len(want) {
		t.Fatalf("got %v, want %v", servers, want)
	}
	for i, w := range want {
		if servers[i].String() != w {
			t.Errorf("server %d = %s, want %s", i, servers[i], w)
		}
	}
}

func TestSSIDFromIEs(t *testing.T) {
	// Element 0 (SSID) "iPulse-Test", followed by element 1 (supported rates).
	ssid := "iPulse-Test"
	ies := append([]byte{0, byte(len(ssid))}, []byte(ssid)...)
	ies = append(ies, 1, 2, 0x82, 0x84)
	if got := ssidFromIEs(ies); got != ssid {
		t.Errorf("ssidFromIEs = %q, want %q", got, ssid)
	}
	// A hidden network advertises a zero-length SSID.
	if got := ssidFromIEs([]byte{0, 0, 1, 1, 0x82}); got != "" {
		t.Errorf("hidden SSID should be empty, got %q", got)
	}
	// Truncated element must not panic or over-read.
	if got := ssidFromIEs([]byte{0, 40, 'a', 'b'}); got != "" {
		t.Errorf("truncated IE should yield empty, got %q", got)
	}
}

func TestSanitizeSSIDStripsControlCharacters(t *testing.T) {
	if got := sanitizeSSID("net\x00work\n\x1b[31m"); got != "network[31m" {
		t.Errorf("sanitizeSSID = %q", got)
	}
}

func TestNormaliseDBM(t *testing.T) {
	cases := map[int]int{-57: -57, 200: -56, 0: 0, 256: 0}
	for in, want := range cases {
		if got := normaliseDBM(in); got != want {
			t.Errorf("normaliseDBM(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNetlinkAttributeRoundTrip(t *testing.T) {
	buf := putAttrU32(nil, 3, 42)
	buf = putAttrString(buf, 4, "wlan0")
	// A 5-byte value must be padded to 8 so the following attribute stays aligned.
	buf = putAttr(buf, 6, []byte{1, 2, 3, 4, 5})
	buf = putAttrU32(buf, 7, 0xdeadbeef)

	attrs, err := parseAttrs(buf)
	if err != nil {
		t.Fatal(err)
	}
	if attrU32(attrs[3]) != 42 {
		t.Errorf("u32 attribute = %d", attrU32(attrs[3]))
	}
	if attrString(attrs[4]) != "wlan0" {
		t.Errorf("string attribute = %q", attrString(attrs[4]))
	}
	if len(attrs[6]) != 5 {
		t.Errorf("byte attribute length = %d, want 5", len(attrs[6]))
	}
	if attrU32(attrs[7]) != 0xdeadbeef {
		t.Errorf("attribute after padding = %x", attrU32(attrs[7]))
	}
	if _, err := parseAttrs([]byte{2, 0, 0, 0}); err == nil {
		t.Error("expected malformed attribute to be rejected")
	}
}

func TestRateFromNested(t *testing.T) {
	// BITRATE32 = 5764 (units of 100 kbps) -> 576.4 Mbps
	nested := putAttrU32(nil, rateInfoBitrate32, 5764)
	if got := rateFromNested(nested); got != 576.4 {
		t.Errorf("rateFromNested = %v, want 576.4", got)
	}
	// The 16-bit form is used by older drivers.
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], 650)
	nested16 := putAttr(nil, rateInfoBitrate, b[:])
	if got := rateFromNested(nested16); got != 65 {
		t.Errorf("rateFromNested(16-bit) = %v, want 65", got)
	}
	if got := rateFromNested(nil); got != 0 {
		t.Errorf("empty nested attribute should give 0, got %v", got)
	}
}

// TestLiveCollectors exercises the real collectors. Assertions are limited to what must
// hold on any Linux host so this is safe in a container.
func TestLiveCollectors(t *testing.T) {
	p := New()

	routes, err := p.Routes()
	if err != nil {
		t.Fatalf("routes: %v", err)
	}
	for _, r := range routes {
		if r.Interface == "" {
			t.Errorf("route with no interface: %+v", r)
		}
		if !r.Destination.IsValid() {
			t.Errorf("route with invalid destination: %+v", r)
		}
	}

	conns, err := p.Connections(types.ConnOptions{TCP: true, UDP: true, Max: 50})
	if err != nil {
		t.Fatalf("connections: %v", err)
	}
	for _, c := range conns {
		if c.Protocol != "tcp" && c.Protocol != "udp" {
			t.Errorf("unexpected protocol %q", c.Protocol)
		}
		if !c.Local.Addr().IsValid() {
			t.Errorf("connection with invalid local address: %+v", c)
		}
	}

	if servers, err := p.DNSServers(); err == nil {
		for _, s := range servers {
			if s.Port() != 53 {
				t.Errorf("resolver %s should default to port 53", s)
			}
		}
	}

	// Loopback must always be present and up.
	ifaces, err := p.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var lo *types.Interface
	for i := range ifaces {
		if ifaces[i].Name == "lo" {
			lo = &ifaces[i]
		}
	}
	if lo == nil {
		t.Fatal("no loopback interface found")
	}
	if !lo.Up || lo.Type != types.IfaceLoopback {
		t.Errorf("loopback looks wrong: %+v", lo)
	}
	if _, ok := netip.AddrFromSlice(nil); ok {
		t.Error("sanity check failed")
	}
}
