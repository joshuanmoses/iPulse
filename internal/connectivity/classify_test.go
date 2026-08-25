package connectivity

import (
	"strings"
	"testing"
)

// healthyEvidence is a fully working connection. Each simulation below starts from it
// and breaks exactly one thing, which is what makes the expected classification obvious.
func healthyEvidence() Evidence {
	return Evidence{
		LoopbackOK:          true,
		InterfaceUp:         true,
		InterfaceName:       "eth0",
		InterfaceType:       "ethernet",
		CarrierPresent:      true,
		HasRoutableAddr:     true,
		LocalIP:             "192.168.1.20",
		DefaultRoutePresent: true,
		Gateway:             "192.168.1.1",
		GatewayReachable:    true,
		GatewayRTTMS:        1.2,

		DNSServersConfigured: 2,
		DNSServersTested:     2,
		DNSServersFailed:     0,
		DNSResolves:          true,

		IPLiteralsTested:    4,
		IPLiteralsReachable: 4,

		HTTPSTested:    3,
		HTTPSReachable: 3,
	}
}

// TestSimulatedFailures is the outage simulation suite: every fault the requirements
// call out is reproduced as evidence and must classify correctly, with no network
// involved.
func TestSimulatedFailures(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*Evidence)
		want   Classification
	}{
		{
			name:   "healthy connection",
			break_: func(e *Evidence) {},
			want:   ClassHealthy,
		},
		{
			name: "ISP outage: local network fine, nothing external reachable",
			break_: func(e *Evidence) {
				e.IPLiteralsReachable = 0
				e.UnreachableLiterals = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}
				e.HTTPSReachable = 0
				// A local cache or the router still answers DNS.
				e.DNSResolves = true
			},
			want: ClassISPOutage,
		},
		{
			name: "DNS outage: resolvers fail while the path works",
			break_: func(e *Evidence) {
				e.DNSResolves = false
				e.DNSServersFailed = 2
				e.DNSFailedServers = []string{"192.168.1.1:53"}
				e.HTTPSReachable = 0 // name-based targets cannot resolve
			},
			want: ClassDNSFailure,
		},
		{
			name: "DNS outage confirmed by working public resolvers",
			break_: func(e *Evidence) {
				e.DNSResolves = false
				e.DNSServersFailed = 2
				e.FallbackDNSResolves = true
				e.HTTPSReachable = 0
			},
			want: ClassDNSFailure,
		},
		{
			name: "gateway outage: interface up, gateway silent, nothing beyond",
			break_: func(e *Evidence) {
				e.GatewayReachable = false
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
				e.DNSResolves = false
			},
			want: ClassGatewayFailure,
		},
		{
			name: "local interface failure: no interface up",
			break_: func(e *Evidence) {
				e.InterfaceUp = false
				e.CarrierPresent = false
				e.HasRoutableAddr = false
				e.GatewayReachable = false
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
				e.DNSResolves = false
			},
			want: ClassLocalInterfaceFail,
		},
		{
			name: "local interface failure: link-local address only (DHCP failed)",
			break_: func(e *Evidence) {
				e.HasRoutableAddr = false
				e.GatewayReachable = false
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
				e.DNSResolves = false
			},
			want: ClassLocalInterfaceFail,
		},
		{
			name: "routing failure: no default route",
			break_: func(e *Evidence) {
				e.DefaultRoutePresent = false
				e.GatewayReachable = false
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
			},
			want: ClassRoutingFailure,
		},
		{
			name: "partial connectivity: some external targets unreachable",
			break_: func(e *Evidence) {
				e.IPLiteralsReachable = 2
				e.UnreachableLiterals = []string{"9.9.9.9", "208.67.222.222"}
				e.HTTPSReachable = 1
			},
			want: ClassPartialConnectivity,
		},
		{
			name: "partial connectivity: IP reachable but no HTTPS completes",
			break_: func(e *Evidence) {
				e.HTTPSReachable = 0
			},
			want: ClassPartialConnectivity,
		},
		{
			name: "Wi-Fi degradation explains total external loss",
			break_: func(e *Evidence) {
				e.InterfaceType = "wireless"
				e.WiFiAssociated = true
				e.WiFiSignalDBM = -84
				e.WiFiWeak = true
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
				e.DNSResolves = false
			},
			want: ClassWiFiDegradation,
		},
		{
			name: "wireless radio up but not associated is a local failure",
			break_: func(e *Evidence) {
				e.InterfaceType = "wireless"
				e.WiFiAssociated = false
				e.GatewayReachable = false
				e.IPLiteralsReachable = 0
				e.HTTPSReachable = 0
				e.DNSResolves = false
			},
			want: ClassLocalInterfaceFail,
		},
		{
			name: "captive portal intercepts every HTTPS session",
			break_: func(e *Evidence) {
				e.HTTPSReachable = 0
				e.CaptivePortalSuspected = true
			},
			want: ClassCaptivePortal,
		},
		{
			name: "unresponsive gateway with a working Internet is not a fault",
			break_: func(e *Evidence) {
				// Many routers simply do not answer probes.
				e.GatewayReachable = false
			},
			want: ClassHealthy,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := healthyEvidence()
			c.break_(&ev)
			got := Classify(ev)
			if got != c.want {
				t.Errorf("Classify = %s, want %s\nevidence: %s", got, c.want, ev.Summary())
			}
			cause := ProbableCause(got, ev)
			if cause == "" || cause == "undetermined" {
				t.Errorf("classification %s produced no probable cause", got)
			}
			if got.IsFailure() != (c.want != ClassHealthy) {
				t.Errorf("IsFailure() = %v for %s", got.IsFailure(), got)
			}
		})
	}
}

// TestClassifyIsDeterministic guards the property the whole design relies on: the same
// evidence always yields the same conclusion.
func TestClassifyIsDeterministic(t *testing.T) {
	ev := healthyEvidence()
	ev.DNSResolves = false
	ev.DNSServersFailed = 2
	ev.HTTPSReachable = 0
	first := Classify(ev)
	for i := 0; i < 100; i++ {
		if got := Classify(ev); got != first {
			t.Fatalf("classification changed between runs: %s then %s", first, got)
		}
	}
}

func TestEventCodesAreDistinct(t *testing.T) {
	seen := map[int]Classification{}
	for _, c := range []Classification{
		ClassISPOutage, ClassDNSFailure, ClassGatewayFailure, ClassLocalInterfaceFail,
		ClassPartialConnectivity, ClassRoutingFailure, ClassWiFiDegradation,
	} {
		code := c.EventCode()
		if prev, dup := seen[code]; dup {
			t.Errorf("classifications %s and %s share event code %d", prev, c, code)
		}
		seen[code] = c
	}
}

func TestEvidenceSummaryAndJSON(t *testing.T) {
	ev := healthyEvidence()
	ev.DNSFailedServers = []string{"192.168.1.1:53"}
	summary := ev.Summary()
	for _, want := range []string{"GatewayReachable=true", "DNSResolves=true", "Literals=4/4", "HTTPS=3/3"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q: %s", want, summary)
		}
	}
	js := ev.JSON()
	if !strings.Contains(js, `"gateway_reachable":true`) {
		t.Errorf("evidence JSON is missing fields: %s", js)
	}
}

func TestTrimError(t *testing.T) {
	if got := trimError(nil); got != "" {
		t.Errorf("nil error should render empty, got %q", got)
	}
}
