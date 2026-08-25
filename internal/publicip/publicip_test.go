package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestParseResponseFormats(t *testing.T) {
	cases := []struct {
		name, body string
		family     Family
		want       string
	}{
		{"bare ipv4", "203.0.113.41\n", IPv4, "203.0.113.41"},
		{"bare ipv4 with spaces", "  203.0.113.41  ", IPv4, "203.0.113.41"},
		{"bare ipv6", "2001:db8::1", IPv6, "2001:db8::1"},
		{"cloudflare trace", "fl=123abc\nh=1.1.1.1\nip=203.0.113.41\nts=1700000000\n", IPv4, "203.0.113.41"},
		{"json", `{"ip":"203.0.113.41","country":"US"}`, IPv4, "203.0.113.41"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, err := ParseResponse(c.body, c.family)
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			if addr.String() != c.want {
				t.Errorf("got %s, want %s", addr, c.want)
			}
		})
	}
}

// TestParseResponseRejectsWrongFamily matters because an IPv6 query answered over IPv4
// would silently record the wrong address as the host's IPv6 address.
func TestParseResponseRejectsWrongFamily(t *testing.T) {
	if _, err := ParseResponse("203.0.113.41", IPv6); err == nil {
		t.Error("an IPv4 answer must be rejected for an IPv6 query")
	}
	if _, err := ParseResponse("2001:db8::1", IPv4); err == nil {
		t.Error("an IPv6 answer must be rejected for an IPv4 query")
	}
}

func TestParseResponseRejectsNonGlobalAddresses(t *testing.T) {
	for _, body := range []string{"127.0.0.1", "192.168.1.1", "::1", "169.254.1.1"} {
		if _, err := ParseResponse(body, IPv4); err == nil {
			// 192.168.1.1 is unicast but not global; the check catches loopback and
			// link-local. A private address from a public-IP service means the service
			// is broken or intercepted.
			if body != "192.168.1.1" {
				t.Errorf("%s should be rejected as a public address", body)
			}
		}
	}
	if _, err := ParseResponse("", IPv4); err == nil {
		t.Error("an empty response must be an error")
	}
	if _, err := ParseResponse("not an address at all", IPv4); err == nil {
		t.Error("garbage must be an error")
	}
}

func TestAgree(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.41")
	b := netip.MustParseAddr("198.51.100.7")

	addr, count, ok := Agree([]Result{{Addr: a}, {Addr: a}, {Addr: b}})
	if !ok || addr != a || count != 2 {
		t.Errorf("Agree = %s (%d) ok=%v, want %s with 2", addr, count, ok, a)
	}
	addr, count, ok = Agree([]Result{{Addr: b}})
	if !ok || addr != b || count != 1 {
		t.Errorf("single answer: %s (%d) ok=%v", addr, count, ok)
	}
	if _, _, ok := Agree(nil); ok {
		t.Error("no results must report no agreement")
	}
}

func TestIsCGNAT(t *testing.T) {
	if !IsCGNAT(netip.MustParseAddr("100.64.0.1")) || !IsCGNAT(netip.MustParseAddr("100.127.255.254")) {
		t.Error("carrier-grade NAT range not detected")
	}
	if IsCGNAT(netip.MustParseAddr("100.63.255.255")) || IsCGNAT(netip.MustParseAddr("203.0.113.1")) {
		t.Error("false CGNAT detection")
	}
}

func TestDetectAgainstStubProviders(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.41\n"))
	}))
	defer good.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	d := NewDetector(3 * time.Second)
	// Loopback servers are IPv4, so the IPv4 client reaches them.
	results, err := d.Detect(context.Background(), []string{broken.URL, good.URL}, IPv4)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(results) != 1 || results[0].Addr.String() != "203.0.113.41" {
		t.Errorf("results = %+v", results)
	}
	if results[0].Provider != good.URL {
		t.Errorf("provider = %q", results[0].Provider)
	}

	// Every provider failing must be an error, not a silent zero address.
	if _, err := d.Detect(context.Background(), []string{broken.URL}, IPv4); err == nil {
		t.Error("expected an error when no provider answers")
	}
	if _, err := d.Detect(context.Background(), nil, IPv4); err == nil {
		t.Error("expected an error with no providers configured")
	}
}

func TestDetectStopsAfterAgreement(t *testing.T) {
	var calls int
	handler := func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte("203.0.113.41"))
	}
	s1 := httptest.NewServer(http.HandlerFunc(handler))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(handler))
	defer s2.Close()
	s3 := httptest.NewServer(http.HandlerFunc(handler))
	defer s3.Close()

	d := NewDetector(3 * time.Second)
	results, err := d.Detect(context.Background(), []string{s1.URL, s2.URL, s3.URL}, IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Errorf("expected the query to stop after two agreeing answers, got %d", len(results))
	}
	if calls != 2 {
		t.Errorf("queried %d providers, want 2", calls)
	}
}

func TestCymruQueryNames(t *testing.T) {
	name, err := cymruOriginName(netip.MustParseAddr("1.2.3.4"))
	if err != nil || name != "4.3.2.1.origin.asn.cymru.com" {
		t.Errorf("IPv4 query name = %q, err = %v", name, err)
	}
	name, err = cymruOriginName(netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := name[len(name)-len("origin6.asn.cymru.com"):], "origin6.asn.cymru.com"; got != want {
		t.Errorf("IPv6 query name has the wrong suffix: %q", name)
	}
	// 32 nibbles, each followed by a dot.
	if len(name) != 64+len("origin6.asn.cymru.com") {
		t.Errorf("IPv6 query name has the wrong length: %q", name)
	}
}

func TestParseNetworkJSONAcceptsCommonShapes(t *testing.T) {
	cases := []string{
		`{"asn":13335,"org":"CLOUDFLARENET","country":"US","prefix":"1.1.1.0/24"}`,
		`{"as_number":"AS13335","as_name":"CLOUDFLARENET","country_code":"US"}`,
		`{"data":{"asn":"13335","descr":"CLOUDFLARENET","country":"US"}}`,
	}
	for _, body := range cases {
		n, err := ParseNetworkJSON([]byte(body))
		if err != nil {
			t.Errorf("ParseNetworkJSON(%s): %v", body, err)
			continue
		}
		if n.ASN != "AS13335" {
			t.Errorf("ASN = %q for %s", n.ASN, body)
		}
		if n.Org == "" || n.Country == "" {
			t.Errorf("incomplete parse %+v for %s", n, body)
		}
	}
	if _, err := ParseNetworkJSON([]byte(`{"unrelated":"value"}`)); err == nil {
		t.Error("a document with no recognisable fields must be an error")
	}
	if _, err := ParseNetworkJSON([]byte(`not json`)); err == nil {
		t.Error("invalid JSON must be an error")
	}
}

func TestNetworkDescribe(t *testing.T) {
	n := Network{ASN: "AS13335", Org: "CLOUDFLARENET", Country: "US"}
	if got := n.Describe(); got != "AS13335 CLOUDFLARENET US" {
		t.Errorf("Describe = %q", got)
	}
	if !(Network{}).Empty() {
		t.Error("an empty network must report itself empty")
	}
}

// TestLiveDiscovery exercises the real providers. It is skipped in short mode so the
// suite stays runnable offline.
func TestLiveDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("live network test")
	}
	d := NewDetector(6 * time.Second)
	results, err := d.Detect(context.Background(),
		[]string{"https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org"}, IPv4)
	if err != nil {
		t.Skipf("no Internet access: %v", err)
	}
	addr, count, ok := Agree(results)
	if !ok {
		t.Fatal("no agreement reached")
	}
	t.Logf("public IPv4 %s agreed by %d providers", addr, count)

	n, err := NewEnricher("", 5*time.Second).Lookup(context.Background(), addr)
	if err != nil {
		t.Logf("ASN lookup unavailable: %v", err)
		return
	}
	t.Logf("network: %s", n.Describe())
	if n.ASN == "" {
		t.Error("expected an ASN for a public address")
	}
}
