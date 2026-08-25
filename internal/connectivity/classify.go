package connectivity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Classification is the conclusion of the diagnostic ladder.
type Classification string

// Classifications. These strings are stored in outage records and appear in events, so
// they are stable identifiers.
const (
	ClassHealthy             Classification = "HEALTHY"
	ClassInternetOutage      Classification = "INTERNET_OUTAGE"
	ClassISPOutage           Classification = "ISP_OUTAGE"
	ClassDNSFailure          Classification = "DNS_FAILURE"
	ClassGatewayFailure      Classification = "GATEWAY_FAILURE"
	ClassLocalInterfaceFail  Classification = "LOCAL_INTERFACE_FAILURE"
	ClassWiFiDegradation     Classification = "WIFI_DEGRADATION"
	ClassPartialConnectivity Classification = "PARTIAL_CONNECTIVITY"
	ClassRoutingFailure      Classification = "ROUTING_FAILURE"
	ClassCaptivePortal       Classification = "CAPTIVE_PORTAL"
	ClassUnknown             Classification = "UNKNOWN"
)

// Evidence is what the diagnostic ladder observed. Every field is a fact, not a
// conclusion, so the same evidence always produces the same classification.
type Evidence struct {
	// Layer 1: the local device.
	LoopbackOK bool `json:"loopback_ok"`

	// Layer 2: the network interface.
	InterfaceUp     bool   `json:"interface_up"`
	InterfaceName   string `json:"interface,omitempty"`
	InterfaceType   string `json:"interface_type,omitempty"`
	CarrierPresent  bool   `json:"carrier_present"`
	HasRoutableAddr bool   `json:"has_routable_address"`
	LocalIP         string `json:"local_ip,omitempty"`
	// WiFi context, when the active interface is wireless.
	WiFiAssociated bool `json:"wifi_associated,omitempty"`
	WiFiSignalDBM  int  `json:"wifi_signal_dbm,omitempty"`
	WiFiWeak       bool `json:"wifi_weak,omitempty"`

	// Layer 3: the default gateway.
	DefaultRoutePresent bool    `json:"default_route_present"`
	Gateway             string  `json:"gateway,omitempty"`
	GatewayReachable    bool    `json:"gateway_reachable"`
	GatewayRTTMS        float64 `json:"gateway_rtt_ms,omitempty"`
	GatewayMethod       string  `json:"gateway_method,omitempty"`

	// Layer 4: DNS.
	DNSServersConfigured int      `json:"dns_servers_configured"`
	DNSServersTested     int      `json:"dns_servers_tested"`
	DNSServersFailed     int      `json:"dns_servers_failed"`
	DNSResolves          bool     `json:"dns_resolves"`
	DNSFailedServers     []string `json:"dns_failed_servers,omitempty"`
	// FallbackDNSResolves records whether a public resolver worked when the configured
	// ones did not, which separates a broken local resolver from a broken network.
	FallbackDNSResolves bool `json:"fallback_dns_resolves"`

	// Layer 5: the ISP path, tested with IP literals so DNS cannot influence it.
	IPLiteralsTested    int      `json:"ip_literals_tested"`
	IPLiteralsReachable int      `json:"ip_literals_reachable"`
	UnreachableLiterals []string `json:"unreachable_literals,omitempty"`

	// Layer 6: the Internet, tested with full HTTPS sessions.
	HTTPSTested      int      `json:"https_tested"`
	HTTPSReachable   int      `json:"https_reachable"`
	UnreachableHTTPS []string `json:"unreachable_https,omitempty"`
	// CaptivePortalSuspected is set when HTTPS requests are answered by something
	// unexpected, which is how a hotel or airport network fails.
	CaptivePortalSuspected bool `json:"captive_portal_suspected,omitempty"`

	// Context.
	VPNActive bool `json:"vpn_active,omitempty"`
}

// ExternalIPReachable reports whether any DNS-free external target answered.
func (e Evidence) ExternalIPReachable() bool { return e.IPLiteralsReachable > 0 }

// HTTPSReachableAny reports whether any full HTTPS session completed.
func (e Evidence) HTTPSReachableAny() bool { return e.HTTPSReachable > 0 }

// Classify reduces evidence to a conclusion.
//
// The order of the checks is the diagnostic ladder itself: the lowest broken layer is
// the answer, because a failure there explains every failure above it. Reporting an ISP
// outage when the cable is unplugged would be worse than useless.
func Classify(e Evidence) Classification {
	// Layer 2: no usable interface. Nothing above this can work.
	if !e.InterfaceUp || !e.HasRoutableAddr {
		return ClassLocalInterfaceFail
	}
	// A wireless interface that is up but not associated is a local failure too.
	if e.InterfaceType == "wireless" && !e.WiFiAssociated && !e.GatewayReachable {
		return ClassLocalInterfaceFail
	}

	// Layer 3: no default route, or a gateway that does not answer.
	if !e.DefaultRoutePresent {
		return ClassRoutingFailure
	}
	if !e.GatewayReachable {
		// A gateway that ignores probes while the Internet works is not a fault: some
		// routers do not answer ICMP or TCP on any port. Only conclude gateway failure
		// when nothing beyond it works either.
		if !e.ExternalIPReachable() && !e.HTTPSReachableAny() {
			return ClassGatewayFailure
		}
	}

	// Everything above the gateway works: nothing is wrong.
	if e.HTTPSReachableAny() && e.DNSResolves &&
		(e.IPLiteralsTested == 0 || e.IPLiteralsReachable == e.IPLiteralsTested) {
		return ClassHealthy
	}

	// Layer 5: the path off this network is broken while the local network is fine.
	if e.ExternalIPReachable() {
		// Some external targets answer and others do not.
		if e.IPLiteralsTested > 0 && e.IPLiteralsReachable < e.IPLiteralsTested {
			// Layer 4 first: name resolution is a more specific explanation than
			// partial reachability when nothing resolves.
			if !e.DNSResolves && e.DNSServersTested > 0 {
				return ClassDNSFailure
			}
			return ClassPartialConnectivity
		}
		// IP reachability is complete, so the failure is DNS or the application layer.
		if !e.DNSResolves && e.DNSServersTested > 0 {
			return ClassDNSFailure
		}
		if e.CaptivePortalSuspected {
			return ClassCaptivePortal
		}
		if e.HTTPSTested > 0 && e.HTTPSReachable == 0 {
			// TCP to literals works but no HTTPS session completes: something is
			// interfering above the network layer.
			return ClassPartialConnectivity
		}
		if e.HTTPSTested > 0 && e.HTTPSReachable < e.HTTPSTested {
			return ClassPartialConnectivity
		}
		return ClassHealthy
	}

	// No external target answers at all, but the local network is healthy.
	if e.GatewayReachable {
		// Wi-Fi quality is worth naming when it is bad enough to explain the loss.
		if e.WiFiWeak {
			return ClassWiFiDegradation
		}
		if e.DNSResolves {
			// DNS answers (from a local cache or the router) but nothing routes.
			return ClassISPOutage
		}
		if e.FallbackDNSResolves {
			return ClassDNSFailure
		}
		return ClassISPOutage
	}

	return ClassInternetOutage
}

// ProbableCause returns the operator-facing explanation for a classification.
func ProbableCause(c Classification, e Evidence) string {
	switch c {
	case ClassHealthy:
		return "no fault detected"
	case ClassLocalInterfaceFail:
		switch {
		case !e.InterfaceUp:
			return "no network interface is up"
		case !e.CarrierPresent:
			return "interface is up but has no carrier (cable unplugged, or radio not associated)"
		case !e.HasRoutableAddr:
			return "interface has no routable address (DHCP failure or link-local only)"
		default:
			return "local network interface failure"
		}
	case ClassRoutingFailure:
		if e.VPNActive {
			return "no usable default route; a VPN or tunnel may have removed or replaced it"
		}
		return "no default route is present"
	case ClassGatewayFailure:
		return fmt.Sprintf("default gateway %s is not responding while the interface is up", e.Gateway)
	case ClassDNSFailure:
		if e.FallbackDNSResolves {
			return "configured resolvers are failing while public resolvers work"
		}
		return "name resolution is failing while the network path is working"
	case ClassISPOutage:
		return "gateway and local network are healthy but no external destination is reachable: upstream or ISP failure"
	case ClassPartialConnectivity:
		return "some destinations are reachable and others are not: likely upstream routing or filtering"
	case ClassWiFiDegradation:
		return fmt.Sprintf("wireless signal is weak (%d dBm) and is degrading connectivity", e.WiFiSignalDBM)
	case ClassCaptivePortal:
		return "HTTPS requests are being intercepted: a captive portal is probably requiring sign-in"
	case ClassInternetOutage:
		return "no connectivity beyond the local device"
	}
	return "undetermined"
}

// Severity maps a classification onto the event severity used when reporting it.
func (c Classification) IsFailure() bool { return c != ClassHealthy && c != ClassUnknown }

// EventCode returns the specific event code for a classification, so each cause is
// reported under its own identifier rather than a generic one.
func (c Classification) EventCode() int {
	switch c {
	case ClassISPOutage:
		return 3004
	case ClassDNSFailure:
		return 3005
	case ClassGatewayFailure:
		return 3006
	case ClassLocalInterfaceFail:
		return 3007
	case ClassPartialConnectivity:
		return 3008
	case ClassRoutingFailure:
		return 3009
	case ClassWiFiDegradation:
		return 3010
	}
	return 3001
}

// JSON renders evidence for storage in an outage record.
func (e Evidence) JSON() string {
	b, err := json.Marshal(e)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Summary renders the evidence as a compact, readable line for the log body.
func (e Evidence) Summary() string {
	parts := []string{
		fmt.Sprintf("InterfaceUp=%t", e.InterfaceUp),
		fmt.Sprintf("GatewayReachable=%t", e.GatewayReachable),
		fmt.Sprintf("DNSResolves=%t", e.DNSResolves),
		fmt.Sprintf("ExternalIPReachable=%t", e.ExternalIPReachable()),
		fmt.Sprintf("HTTPSReachable=%t", e.HTTPSReachableAny()),
	}
	if e.IPLiteralsTested > 0 {
		parts = append(parts, fmt.Sprintf("Literals=%d/%d", e.IPLiteralsReachable, e.IPLiteralsTested))
	}
	if e.HTTPSTested > 0 {
		parts = append(parts, fmt.Sprintf("HTTPS=%d/%d", e.HTTPSReachable, e.HTTPSTested))
	}
	if e.DNSServersTested > 0 {
		parts = append(parts, fmt.Sprintf("DNS=%d/%d", e.DNSServersTested-e.DNSServersFailed, e.DNSServersTested))
	}
	sort.Strings(e.DNSFailedServers)
	if len(e.DNSFailedServers) > 0 {
		parts = append(parts, "FailedResolvers="+strings.Join(e.DNSFailedServers, "|"))
	}
	return strings.Join(parts, " ")
}
