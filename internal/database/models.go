package database

import (
	"time"

	"github.com/ipulse/ipulse/internal/events"
)

// Measurement is one stored numeric observation.
type Measurement struct {
	ID     int64     `json:"id,omitempty"`
	Time   time.Time `json:"time"`
	Metric string    `json:"metric"`
	Value  float64   `json:"value"`
	Unit   string    `json:"unit,omitempty"`
	// Target is the dimension the value belongs to: a probe target, an interface, a
	// destination or a process. Empty means "the connection as a whole".
	Target string `json:"target,omitempty"`
	OK     bool   `json:"ok"`
	Meta   string `json:"meta,omitempty"`
}

// Metric names. These strings are stored in the database and referenced by the
// baseline engine, the detectors and the API, so they are declared once here.
const (
	MetricLatencyMS       = "latency_ms"
	MetricJitterMS        = "jitter_ms"
	MetricPacketLossPct   = "packet_loss_pct"
	MetricGatewayRTTMS    = "gateway_rtt_ms"
	MetricDNSMS           = "dns_ms"
	MetricDownloadMbps    = "download_mbps"
	MetricUploadMbps      = "upload_mbps"
	MetricLightDownMbps   = "light_download_mbps"
	MetricTCPConnectMS    = "tcp_connect_ms"
	MetricHTTPSTTFBMS     = "https_ttfb_ms"
	MetricRxBps           = "rx_bps"
	MetricTxBps           = "tx_bps"
	MetricRxBytesWindow   = "rx_bytes_window"
	MetricTxBytesWindow   = "tx_bytes_window"
	MetricConnCount       = "connection_count"
	MetricInternalHosts   = "internal_hosts"
	MetricDistinctDests   = "distinct_destinations"
	MetricWiFiSignalDBM   = "wifi_signal_dbm"
	MetricWiFiLinkMbps    = "wifi_link_mbps"
	MetricHealthScore     = "health_score"
	MetricAvailabilityPct = "availability_pct"
	MetricHopCount        = "hop_count"
	MetricProcTxBytes     = "process_tx_bytes"
)

// SpeedTest is a stored speed-test result.
type SpeedTest struct {
	ID               int64         `json:"id,omitempty"`
	Time             time.Time     `json:"time"`
	Mode             string        `json:"mode"`
	Provider         string        `json:"provider,omitempty"`
	Endpoint         string        `json:"endpoint,omitempty"`
	EndpointLocation string        `json:"endpoint_location,omitempty"`
	DownloadMbps     float64       `json:"download_mbps"`
	UploadMbps       float64       `json:"upload_mbps"`
	DownloadP90Mbps  float64       `json:"download_p90_mbps,omitempty"`
	UploadP90Mbps    float64       `json:"upload_p90_mbps,omitempty"`
	LatencyMS        float64       `json:"latency_ms"`
	JitterMS         float64       `json:"jitter_ms"`
	PacketLossPct    float64       `json:"packet_loss_pct"`
	TCPConnectMS     float64       `json:"tcp_connect_ms,omitempty"`
	DNSMS            float64       `json:"dns_ms,omitempty"`
	TTFBMS           float64       `json:"ttfb_ms,omitempty"`
	BytesDown        int64         `json:"bytes_down,omitempty"`
	BytesUp          int64         `json:"bytes_up,omitempty"`
	Streams          int           `json:"streams,omitempty"`
	Duration         time.Duration `json:"duration_ms,omitempty"`
	Status           string        `json:"status"`
	Error            string        `json:"error,omitempty"`
	ExpectedDownload float64       `json:"expected_download_mbps,omitempty"`
	ExpectedUpload   float64       `json:"expected_upload_mbps,omitempty"`
	Interface        string        `json:"interface,omitempty"`
	PublicIP         string        `json:"public_ip,omitempty"`
	ISP              string        `json:"isp,omitempty"`
	Raw              string        `json:"raw,omitempty"`
}

// Speed-test modes.
const (
	SpeedModeFull        = "full"
	SpeedModeLightweight = "lightweight"
	SpeedModeManual      = "manual"
)

// Outage is a recorded loss of connectivity.
type Outage struct {
	ID             int64         `json:"id"`
	Start          time.Time     `json:"start"`
	End            time.Time     `json:"end,omitempty"`
	Duration       time.Duration `json:"duration"`
	Classification string        `json:"classification"`
	ProbableCause  string        `json:"probable_cause"`
	Evidence       string        `json:"evidence,omitempty"`
	Interface      string        `json:"interface,omitempty"`
	Gateway        string        `json:"gateway,omitempty"`
	PublicIP       string        `json:"public_ip,omitempty"`
	Resolved       bool          `json:"resolved"`
	Diagnostics    int           `json:"diagnostics"`
}

// Interface is the stored description of a network interface.
type Interface struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	MAC       string    `json:"mac,omitempty"`
	MTU       int       `json:"mtu,omitempty"`
	SpeedMbps int       `json:"speed_mbps,omitempty"`
	Addresses string    `json:"addresses,omitempty"`
	Up        bool      `json:"up"`
	Wireless  bool      `json:"wireless"`
	IsDefault bool      `json:"is_default"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// InterfaceSample is one counter delta sample for an interface.
type InterfaceSample struct {
	Time      time.Time `json:"time"`
	Interface string    `json:"interface"`
	RxBytes   int64     `json:"rx_bytes"`
	TxBytes   int64     `json:"tx_bytes"`
	RxPackets int64     `json:"rx_packets"`
	TxPackets int64     `json:"tx_packets"`
	RxErrors  int64     `json:"rx_errors"`
	TxErrors  int64     `json:"tx_errors"`
	RxDropped int64     `json:"rx_dropped"`
	TxDropped int64     `json:"tx_dropped"`
	RxBps     float64   `json:"rx_bps"`
	TxBps     float64   `json:"tx_bps"`
	// SelfRxBps and SelfTxBps are the portion attributable to iPulse's own speed
	// tests, so detectors can exclude it.
	SelfRxBps float64 `json:"self_rx_bps"`
	SelfTxBps float64 `json:"self_tx_bps"`
}

// WiFiSample is one wireless telemetry sample. No credentials are ever recorded.
type WiFiSample struct {
	Time         time.Time `json:"time"`
	Interface    string    `json:"interface"`
	SSID         string    `json:"ssid,omitempty"`
	BSSID        string    `json:"bssid,omitempty"`
	SignalDBM    int       `json:"signal_dbm"`
	SignalPct    int       `json:"signal_percent"`
	LinkMbps     float64   `json:"link_mbps"`
	RxMbps       float64   `json:"rx_mbps,omitempty"`
	FrequencyMHz int       `json:"frequency_mhz,omitempty"`
	Channel      int       `json:"channel,omitempty"`
	Band         string    `json:"band,omitempty"`
	NoiseDBM     int       `json:"noise_dbm,omitempty"`
}

// Connection is a stored active-connection record, aggregated across samples.
type Connection struct {
	ID         int64         `json:"id"`
	Key        string        `json:"key"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	Protocol   string        `json:"protocol"`
	LocalIP    string        `json:"local_ip,omitempty"`
	LocalPort  int           `json:"local_port,omitempty"`
	RemoteIP   string        `json:"remote_ip,omitempty"`
	RemotePort int           `json:"remote_port,omitempty"`
	State      string        `json:"state,omitempty"`
	PID        int           `json:"pid,omitempty"`
	Process    string        `json:"process,omitempty"`
	Exe        string        `json:"exe,omitempty"`
	User       string        `json:"user,omitempty"`
	BytesSent  int64         `json:"bytes_sent"`
	BytesRecv  int64         `json:"bytes_recv"`
	Duration   time.Duration `json:"duration"`
	Interface  string        `json:"interface,omitempty"`
	Internal   bool          `json:"internal"`
	Samples    int           `json:"samples"`
}

// Destination is the accumulated history for one remote endpoint.
type Destination struct {
	ID         int64     `json:"id"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort int       `json:"remote_port"`
	Protocol   string    `json:"protocol"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Contacts   int64     `json:"contacts"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
	Processes  string    `json:"processes,omitempty"`
	ReverseDNS string    `json:"reverse_dns,omitempty"`
	ASN        string    `json:"asn,omitempty"`
	ASNOrg     string    `json:"asn_org,omitempty"`
	Country    string    `json:"country,omitempty"`
	EnrichedAt time.Time `json:"enriched_at,omitempty"`
	Internal   bool      `json:"internal"`
	Flagged    bool      `json:"flagged"`
}

// PublicIPRecord is one entry in the public-address history.
type PublicIPRecord struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	Family     string    `json:"family"`
	PreviousIP string    `json:"previous_ip,omitempty"`
	NewIP      string    `json:"new_ip"`
	ASN        string    `json:"asn,omitempty"`
	ASNOrg     string    `json:"asn_org,omitempty"`
	Country    string    `json:"country,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	VPNActive  bool      `json:"vpn_active"`
	CGNAT      bool      `json:"cgnat"`
	Provider   string    `json:"provider,omitempty"`
}

// RoutePath is one stored path measurement.
type RoutePath struct {
	ID          int64     `json:"id"`
	Time        time.Time `json:"time"`
	Destination string    `json:"destination"`
	HopCount    int       `json:"hop_count"`
	Path        string    `json:"path"`
	Changed     bool      `json:"changed"`
	RTTMS       float64   `json:"rtt_ms,omitempty"`
	Method      string    `json:"method,omitempty"`
}

// Indicator is one threat-intelligence indicator held locally.
type Indicator struct {
	ID            int64     `json:"id"`
	Indicator     string    `json:"indicator"`
	Kind          string    `json:"kind"`
	Source        string    `json:"source"`
	Confidence    string    `json:"confidence"`
	Note          string    `json:"note,omitempty"`
	FirstImported time.Time `json:"first_imported"`
	LastInFeed    time.Time `json:"last_in_feed"`
}

// Indicator kinds and confidence values.
const (
	IndicatorIP     = "ip"
	IndicatorCIDR   = "cidr"
	IndicatorDomain = "domain"

	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// ThreatMatch records a connection that matched an indicator.
type ThreatMatch struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	Indicator  string    `json:"indicator"`
	Kind       string    `json:"indicator_kind"`
	Source     string    `json:"source"`
	Confidence string    `json:"confidence"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	RemotePort int       `json:"remote_port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Process    string    `json:"process,omitempty"`
	Exe        string    `json:"exe,omitempty"`
	User       string    `json:"user,omitempty"`
	BytesSent  int64     `json:"bytes_sent,omitempty"`
	BytesRecv  int64     `json:"bytes_recv,omitempty"`
	EventID    int64     `json:"event_id,omitempty"`
}

// FeedStatus is the import state of one threat feed.
type FeedStatus struct {
	Name        string    `json:"name"`
	LastImport  time.Time `json:"last_import,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Indicators  int64     `json:"indicators"`
	LastError   string    `json:"last_error,omitempty"`
	ETag        string    `json:"etag,omitempty"`
}

// BaselineRow is the persisted form of a baseline bucket.
type BaselineRow struct {
	Metric      string    `json:"metric"`
	Dimension   string    `json:"dimension"`
	Bucket      string    `json:"bucket"`
	Samples     int64     `json:"samples"`
	Mean        float64   `json:"mean"`
	M2          float64   `json:"m2"`
	Min         float64   `json:"min"`
	Max         float64   `json:"max"`
	EWMA        float64   `json:"ewma"`
	Median      float64   `json:"median"`
	MAD         float64   `json:"mad"`
	P10         float64   `json:"p10"`
	P25         float64   `json:"p25"`
	P75         float64   `json:"p75"`
	P90         float64   `json:"p90"`
	P95         float64   `json:"p95"`
	P99         float64   `json:"p99"`
	Reservoir   string    `json:"-"`
	Established bool      `json:"established"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// StoredEvent is an event as read back from the database.
type StoredEvent struct {
	ID            int64             `json:"id"`
	Time          time.Time         `json:"time"`
	Code          int               `json:"code"`
	Name          string            `json:"name"`
	Severity      events.Severity   `json:"severity"`
	Category      string            `json:"category"`
	Message       string            `json:"message,omitempty"`
	Process       string            `json:"process,omitempty"`
	Destination   string            `json:"destination,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Suppressed    bool              `json:"suppressed"`
	Fields        map[string]string `json:"fields,omitempty"`
	Rendered      string            `json:"rendered,omitempty"`
}
