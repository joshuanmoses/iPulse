package events

import (
	"fmt"
	"sort"
	"strings"
)

// Event codes. These are stable identifiers: once published, a code keeps its
// meaning forever. New behaviour gets a new code rather than redefining an old one.
const (
	// 1000-1999 Connectivity / Speed
	SpeedTestStarted         = 1001
	SpeedTestCompleted       = 1002
	SpeedTestFailed          = 1003
	ThroughputSample         = 1004
	ConnectivityCheckOK      = 1005
	ConnectivityCheckFailed  = 1006
	InternetRestored         = 1007
	HealthScoreUpdated       = 1008
	HealthScoreDegraded      = 1009
	SpeedEndpointUnavailable = 1010
	SpeedTestSkippedBusy     = 1011

	// 2000-2999 Performance
	DownloadDegradation      = 2001
	UploadDegradation        = 2002
	DownloadBelowISPExpected = 2003
	UploadBelowISPExpected   = 2004
	PerformanceRecovered     = 2005
	ThroughputDegradation    = 2006
	LatencySpike             = 2101
	SustainedHighLatency     = 2102
	JitterDegradation        = 2103
	LatencyDegradation       = 2104
	PacketLossDetected       = 2105
	PacketLossCleared        = 2106
	LocalBandwidthSaturation = 2107
	DNSResponseDegradation   = 2108
	RouteLatencyDegradation  = 2109
	UpstreamDegradation      = 2110

	// 3000-3999 Outages / Availability
	InternetConnectivityLost = 3001
	OutageStarted            = 3002
	OutageEnded              = 3003
	ISPOutage                = 3004
	DNSFailure               = 3005
	GatewayFailure           = 3006
	LocalInterfaceFailure    = 3007
	PartialConnectivity      = 3008
	RoutingFailure           = 3009
	WiFiDegradation          = 3010
	DiagnosticsCompleted     = 3011
	AvailabilityReport       = 3012

	// 4000-4999 Traffic
	BandwidthSpikeDownload  = 4001
	BandwidthSpikeUpload    = 4002
	SustainedBandwidthUsage = 4003
	UnusualOutboundTraffic  = 4004
	SustainedUpload         = 4005
	LargeOutboundTransfer   = 4006
	NewHighVolumeDest       = 4007
	UnusualOvernightTraffic = 4008
	PeriodicSpikePattern    = 4009
	TrafficBaselineReady    = 4010
	ConnectionCountAnomaly  = 4011
	AppUploadAnomaly        = 4012

	// 5000-5999 Security / Destinations
	NewExternalDestination   = 5001
	RareDestinationContact   = 5002
	UnexpectedDestPort       = 5003
	RapidDestinationFanout   = 5004
	KnownMaliciousDest       = 5101
	ThreatIntelligenceMatch  = 5102
	MaliciousDomainConn      = 5103
	ThreatFeedImported       = 5104
	ThreatFeedImportFailed   = 5105
	InternalHostSweep        = 5201
	PossiblePortScan         = 5202
	AbnormalLateralConns     = 5203
	RepeatedInternalFailures = 5204
	RemoteAdminProtoSweep    = 5205

	// 6000-6999 DNS / Routing / Public IP
	DNSResolutionOK      = 6001
	DNSResolutionFailed  = 6002
	DNSServerChanged     = 6003
	DNSSlowResponse      = 6004
	DNSPartialFailure    = 6005
	PublicIPChanged      = 6101
	PublicIPUnavailable  = 6102
	ISPASNChanged        = 6103
	VPNStateChanged      = 6104
	PossibleCGNAT        = 6105
	VPNRoutingChange     = 6106
	RouteChanged         = 6201
	DefaultGatewayChange = 6202
	HopCountChanged      = 6203
	TracerouteCompleted  = 6204
	TracerouteUnavail    = 6205

	// 7000-7999 Interface / Wi-Fi
	InterfaceUp           = 7001
	InterfaceDown         = 7002
	InterfaceChanged      = 7003
	IPAddressChanged      = 7004
	LinkSpeedChanged      = 7005
	InterfaceErrorsRising = 7006
	WiFiConnected         = 7101
	WiFiDisconnected      = 7102
	WiFiSignalDegraded    = 7103
	WiFiSSIDChanged       = 7104
	WiFiLinkSpeedDegraded = 7105
	WiFiMonitoringUnavail = 7106

	// 8000-8999 Service / Agent
	AgentStarted        = 8001
	AgentStopped        = 8002
	ConfigLoaded        = 8003
	ConfigReloaded      = 8004
	ConfigInvalid       = 8005
	ServiceInstalled    = 8006
	ServiceRemoved      = 8007
	DatabaseOpened      = 8008
	RetentionCompleted  = 8009
	LogRotated          = 8010
	APIStarted          = 8011
	APIStopped          = 8012
	SchedulerTaskSkip   = 8013
	PrivilegeLimited    = 8014
	BaselineEstablished = 8015
	ManualTestRequested = 8016

	// 9000-9999 Internal errors
	InternalError  = 9001
	DatabaseError  = 9002
	CollectorError = 9003
	ProbeError     = 9004
	PanicRecovered = 9005
	LogSinkError   = 9006
	TaskTimeout    = 9007
	ConfigWatchErr = 9008
)

// Definition documents one event: what it means, when it fires, which fields it
// carries and what an operator should do about it. The catalog is the single source
// of truth for docs/event-catalog.md, which is generated from it.
type Definition struct {
	Code     int
	Name     string
	Severity Severity
	Category Category
	Summary  string
	Trigger  string
	Fields   []string
	Action   string
}

var catalog = map[int]Definition{}

// Lookup returns the catalog definition for a code.
func Lookup(code int) (Definition, bool) {
	d, ok := catalog[code]
	return d, ok
}

// LookupName resolves an event name (case-insensitive) to its definition.
func LookupName(name string) (Definition, bool) {
	up := strings.ToUpper(strings.TrimSpace(name))
	for _, d := range catalog {
		if d.Name == up {
			return d, true
		}
	}
	return Definition{}, false
}

// All returns every definition ordered by code.
func All() []Definition {
	out := make([]Definition, 0, len(catalog))
	for _, d := range catalog {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Name returns the event name for a code, or a placeholder for unknown codes.
func Name(code int) string {
	if d, ok := catalog[code]; ok {
		return d.Name
	}
	return fmt.Sprintf("UNCATALOGUED_EVENT_%d", code)
}

func register(defs ...Definition) {
	for _, d := range defs {
		if d.Category == "" {
			d.Category = CategoryForCode(d.Code)
		}
		if existing, dup := catalog[d.Code]; dup {
			panic(fmt.Sprintf("events: duplicate event code %d (%s and %s)", d.Code, existing.Name, d.Name))
		}
		if CategoryForCode(d.Code) != d.Category {
			panic(fmt.Sprintf("events: code %d (%s) is outside the range reserved for %s", d.Code, d.Name, d.Category))
		}
		catalog[d.Code] = d
	}
}
