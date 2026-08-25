package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// Condition is one named requirement of a rule. Naming each condition is what lets the
// emitted event list the evidence that satisfied it, instead of asserting a conclusion.
type Condition struct {
	Name  string
	Match func(v *View) (detail string, ok bool)
}

// Rule is one correlation rule.
type Rule struct {
	// Name identifies the rule in logs and tests.
	Name string
	// Conclusion is the event code emitted when the rule fires.
	Conclusion int
	// Cause is the probable-cause text reported with the conclusion.
	Cause string
	// Requires are conditions that must all hold.
	Requires []Condition
	// Suppresses lists the event codes this conclusion explains. They are marked as
	// absorbed so the readable log shows the conclusion rather than the symptoms.
	Suppresses []int
	// Fields adds rule-specific detail to the emitted event.
	Fields func(v *View) events.Fields
	// Cooldown suppresses repeats of this rule.
	Cooldown time.Duration
}

// Match is a fired rule with its evidence.
type Match struct {
	Rule       *Rule
	Time       time.Time
	Cause      string
	Evidence   []string
	SuppressID []int64
	Fields     events.Fields
}

// EvidenceString renders the satisfied conditions for a log field.
func (m Match) EvidenceString() string { return strings.Join(m.Evidence, " + ") }

// DefaultRules returns the shipped rule set.
//
// Each rule encodes a diagnosis an experienced operator would make from the same
// symptoms. They are ordered from most specific to least, and the engine reports the
// first rule that fires, so a specific cause is never masked by a general one.
func DefaultRules() []*Rule {
	return []*Rule{
		saturationRule(),
		wifiDegradationRule(),
		dnsSlownessRule(),
		vpnRoutingRule(),
		ispDegradationRule(),
	}
}

// saturationRule is the classic case: something on the local network is using the link,
// which raises latency and loss and depresses throughput. Reporting it as "the Internet
// is slow" would send the operator to the wrong place entirely.
func saturationRule() *Rule {
	return &Rule{
		Name:       "local-bandwidth-saturation",
		Conclusion: events.LocalBandwidthSaturation,
		Cause:      "LOCAL BANDWIDTH SATURATION",
		Cooldown:   10 * time.Minute,
		Requires: []Condition{
			{
				Name: "bandwidth spike or sustained usage",
				Match: func(v *View) (string, bool) {
					codes := []int{
						events.BandwidthSpikeUpload, events.BandwidthSpikeDownload,
						events.SustainedBandwidthUsage, events.SustainedUpload,
					}
					s, ok := firstEvent(v, codes...)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				Name: "latency degraded",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.LatencyDegradation, events.SustainedHighLatency, events.LatencySpike)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				// Either corroborating symptom is enough: saturation shows up as loss,
				// as a throughput drop, or as both.
				Name: "packet loss or throughput drop",
				Match: func(v *View) (string, bool) {
					if s, ok := firstEvent(v, events.PacketLossDetected); ok {
						return describeEvent(s), true
					}
					if s, ok := firstEvent(v, events.DownloadDegradation, events.ThroughputDegradation,
						events.UploadDegradation); ok {
						return describeEvent(s), true
					}
					// A measured loss above 1 % counts even without an event, because
					// the loss detector has its own persistence requirement.
					if loss, ok := v.Max(database.MetricPacketLossPct); ok && loss >= 1 {
						return fmt.Sprintf("packet loss %.1f%%", loss), true
					}
					return "", false
				},
			},
		},
		Suppresses: []int{
			events.BandwidthSpikeUpload, events.BandwidthSpikeDownload,
			events.SustainedBandwidthUsage, events.LatencyDegradation,
			events.SustainedHighLatency, events.LatencySpike, events.PacketLossDetected,
			events.DownloadDegradation, events.ThroughputDegradation,
		},
		Fields: func(v *View) events.Fields {
			f := events.Fields{}
			direction := "download"
			if v.HasAnyEvent(events.BandwidthSpikeUpload, events.SustainedUpload) {
				direction = "upload"
			}
			if v.HasEvent(events.BandwidthSpikeUpload) && v.HasEvent(events.BandwidthSpikeDownload) {
				direction = "both"
			}
			f = f.Add("Direction", direction)
			if cur, ok := v.Latest(database.MetricLatencyMS); ok {
				f = f.AddUnit("CurrentLatency", cur, "ms")
			}
			if loss, ok := v.Max(database.MetricPacketLossPct); ok {
				f = f.AddPercent("PacketLoss", loss)
			}
			if rx, ok := v.Max(database.MetricRxBps); ok {
				f = f.AddRate("PeakDownload", rx)
			}
			if tx, ok := v.Max(database.MetricTxBps); ok {
				f = f.AddRate("PeakUpload", tx)
			}
			if proc, ok := v.Field(events.BandwidthSpikeUpload, "TopProcess"); ok {
				f = f.Add("TopProcess", proc)
			} else if proc, ok := v.Field(events.SustainedUpload, "TopProcess"); ok {
				f = f.Add("TopProcess", proc)
			}
			return f
		},
	}
}

// wifiDegradationRule attributes latency and loss to the radio rather than the ISP,
// which is the single most common misdiagnosis on a laptop.
func wifiDegradationRule() *Rule {
	return &Rule{
		Name:       "wifi-degradation",
		Conclusion: events.WiFiDegradation,
		Cause:      "WIRELESS LINK DEGRADATION",
		Cooldown:   10 * time.Minute,
		Requires: []Condition{
			{
				Name: "weak or degraded wireless link",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.WiFiSignalDegraded, events.WiFiLinkSpeedDegraded)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				Name: "latency, jitter or loss degraded",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.LatencyDegradation, events.SustainedHighLatency,
						events.JitterDegradation, events.PacketLossDetected)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				// If the gateway is also slow, the problem is on this side of it. A
				// healthy gateway RTT with poor Internet latency points upstream, so the
				// rule declines to blame Wi-Fi.
				Name: "local hop is affected",
				Match: func(v *View) (string, bool) {
					rtt, ok := v.Latest(database.MetricGatewayRTTMS)
					if !ok {
						// No gateway measurement: fall back to the wireless signal
						// alone, which is still the better explanation.
						return "gateway RTT unavailable", true
					}
					if rtt >= 15 {
						return fmt.Sprintf("gateway RTT %.1fms", rtt), true
					}
					return "", false
				},
			},
		},
		Suppresses: []int{
			events.WiFiSignalDegraded, events.WiFiLinkSpeedDegraded,
			events.LatencyDegradation, events.JitterDegradation, events.PacketLossDetected,
		},
		Fields: func(v *View) events.Fields {
			f := events.Fields{}
			if ssid, ok := v.Field(events.WiFiSignalDegraded, "SSID"); ok {
				f = f.Add("SSID", ssid)
			}
			if sig, ok := v.Field(events.WiFiSignalDegraded, "Signal"); ok {
				f = f.Add("Signal", sig)
			}
			if dbm, ok := v.Latest(database.MetricWiFiSignalDBM); ok {
				f = f.Add("SignalDBM", int(dbm))
			}
			if link, ok := v.Latest(database.MetricWiFiLinkMbps); ok {
				f = f.AddUnit("LinkSpeed", link, "Mbps")
			}
			if rtt, ok := v.Latest(database.MetricGatewayRTTMS); ok {
				f = f.AddUnit("GatewayRTT", rtt, "ms")
			}
			if loss, ok := v.Max(database.MetricPacketLossPct); ok {
				f = f.AddPercent("PacketLoss", loss)
			}
			return f
		},
	}
}

// dnsSlownessRule explains "the Internet feels slow" when the network is fine and only
// name resolution is slow. Users experience this as slowness; the fix is a resolver
// change, not an ISP call.
func dnsSlownessRule() *Rule {
	return &Rule{
		Name:       "dns-slowness",
		Conclusion: events.DNSResponseDegradation,
		Cause:      "SLOW NAME RESOLUTION",
		Cooldown:   15 * time.Minute,
		Requires: []Condition{
			{
				Name: "DNS slow or degraded",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.DNSSlowResponse, events.DNSPartialFailure)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				Name: "network path healthy",
				Match: func(v *View) (string, bool) {
					// No outage and no latency degradation in the window: the path is
					// fine, so DNS is the explanation rather than a symptom.
					if v.HasAnyEvent(events.OutageStarted, events.InternetConnectivityLost,
						events.LatencyDegradation, events.SustainedHighLatency) {
						return "", false
					}
					if lat, ok := v.Latest(database.MetricLatencyMS); ok {
						return fmt.Sprintf("latency %.1fms", lat), true
					}
					return "no latency degradation observed", true
				},
			},
		},
		Suppresses: []int{events.DNSSlowResponse},
		Fields: func(v *View) events.Fields {
			f := events.Fields{}
			if cur, ok := v.Latest(database.MetricDNSMS); ok {
				f = f.AddUnit("CurrentDNS", cur, "ms")
			}
			if server, ok := v.Field(events.DNSSlowResponse, "Server"); ok {
				f = f.Add("Server", server)
			}
			if name, ok := v.Field(events.DNSSlowResponse, "Name"); ok {
				f = f.Add("Name", name)
			}
			return f
		},
	}
}

// vpnRoutingRule groups the burst of changes a VPN connection produces into one event,
// instead of leaving the operator to work out that four notices were one action.
func vpnRoutingRule() *Rule {
	return &Rule{
		Name:       "vpn-routing-change",
		Conclusion: events.VPNRoutingChange,
		Cause:      "VPN OR TUNNEL ROUTING CHANGE",
		Cooldown:   2 * time.Minute,
		Requires: []Condition{
			{
				Name: "tunnel state or default route changed",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.VPNStateChanged, events.InterfaceChanged,
						events.DefaultGatewayChange)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				Name: "public IP or resolvers changed with it",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.PublicIPChanged, events.ISPASNChanged, events.DNSServerChanged)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
		},
		Suppresses: []int{
			events.PublicIPChanged, events.ISPASNChanged, events.DNSServerChanged,
			events.DefaultGatewayChange, events.InterfaceChanged,
		},
		Fields: func(v *View) events.Fields {
			f := events.Fields{}
			if newIP, ok := v.Field(events.PublicIPChanged, "NewIP"); ok {
				f = f.Add("PublicIP", newIP)
			}
			if prev, ok := v.Field(events.PublicIPChanged, "PreviousIP"); ok {
				f = f.Add("PreviousPublicIP", prev)
			}
			if iface, ok := v.Field(events.InterfaceChanged, "Current"); ok {
				f = f.Add("Interface", iface)
			} else if iface, ok := v.Field(events.VPNStateChanged, "Interface"); ok {
				f = f.Add("Interface", iface)
			}
			if active, ok := v.Field(events.VPNStateChanged, "VPNActive"); ok {
				f = f.Add("VPNActive", active)
			}
			if gw, ok := v.Field(events.DefaultGatewayChange, "NewGateway"); ok {
				f = f.Add("DefaultRouteVia", gw)
			}
			if servers, ok := v.Field(events.DNSServerChanged, "Current"); ok {
				f = f.Add("DNSServers", servers)
			}
			if asn, ok := v.Field(events.ISPASNChanged, "NewASN"); ok {
				f = f.Add("ASN", asn)
			}
			return f
		},
	}
}

// ispDegradationRule concludes that a throughput drop with a healthy local network is
// the provider's problem, which is exactly the evidence an ISP ticket needs.
func ispDegradationRule() *Rule {
	return &Rule{
		Name:       "isp-performance-degradation",
		Conclusion: events.UpstreamDegradation,
		Cause:      "UPSTREAM OR ISP PERFORMANCE DEGRADATION",
		Cooldown:   30 * time.Minute,
		Requires: []Condition{
			{
				Name: "throughput below baseline or plan",
				Match: func(v *View) (string, bool) {
					s, ok := firstEvent(v, events.DownloadDegradation, events.UploadDegradation,
						events.DownloadBelowISPExpected, events.UploadBelowISPExpected)
					if !ok {
						return "", false
					}
					return describeEvent(s), true
				},
			},
			{
				Name: "local link not saturated",
				Match: func(v *View) (string, bool) {
					if v.HasAnyEvent(events.BandwidthSpikeUpload, events.BandwidthSpikeDownload,
						events.SustainedBandwidthUsage, events.LocalBandwidthSaturation) {
						return "", false
					}
					if rx, ok := v.Max(database.MetricRxBps); ok {
						return fmt.Sprintf("peak local rate %.1fMbps", rx/1e6), true
					}
					return "no local saturation observed", true
				},
			},
			{
				Name: "wireless link healthy or wired",
				Match: func(v *View) (string, bool) {
					if v.HasAnyEvent(events.WiFiSignalDegraded, events.WiFiLinkSpeedDegraded) {
						return "", false
					}
					return "no wireless degradation observed", true
				},
			},
		},
		Suppresses: []int{events.DownloadDegradation, events.UploadDegradation},
		Fields: func(v *View) events.Fields {
			f := events.Fields{}
			if dl, ok := v.Latest(database.MetricDownloadMbps); ok {
				f = f.AddUnit("CurrentDownload", dl, "Mbps")
			}
			if ul, ok := v.Latest(database.MetricUploadMbps); ok {
				f = f.AddUnit("CurrentUpload", ul, "Mbps")
			}
			if dev, ok := v.Field(events.DownloadDegradation, "Deviation"); ok {
				f = f.Add("Deviation", dev)
			}
			return f
		},
	}
}

func firstEvent(v *View, codes ...int) (Signal, bool) {
	list := v.EventsWithCodes(codes...)
	if len(list) == 0 {
		return Signal{}, false
	}
	return list[len(list)-1], true
}

// describeEvent renders a contributing event compactly for the evidence list.
func describeEvent(s Signal) string {
	if len(s.Fields) == 0 {
		return s.Name
	}
	keys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// One representative field keeps the evidence line readable.
	for _, preferred := range []string{"Deviation", "CurrentLatency", "PacketLoss", "CurrentRate",
		"Signal", "ResponseTime", "NewIP", "AverageRate"} {
		if val, ok := s.Fields[preferred]; ok {
			return fmt.Sprintf("%s(%s=%s)", s.Name, preferred, val)
		}
	}
	return fmt.Sprintf("%s(%s=%s)", s.Name, keys[0], s.Fields[keys[0]])
}
