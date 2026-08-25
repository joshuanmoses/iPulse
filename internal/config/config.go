// Package config defines the iPulse YAML configuration schema, its defaults, its
// validation rules and the platform-specific path resolution.
//
// Every field has a documented default, and validation runs before a configuration is
// ever applied: an invalid file leaves the previous configuration in force rather than
// starting the agent in a half-configured state.
package config

// Config is the root of ipulse.yaml.
type Config struct {
	Service      ServiceConfig      `yaml:"service" json:"service"`
	Monitoring   MonitoringConfig   `yaml:"monitoring" json:"monitoring"`
	Connectivity ConnectivityConfig `yaml:"connectivity" json:"connectivity"`
	DNS          DNSConfig          `yaml:"dns" json:"dns"`
	Latency      LatencyConfig      `yaml:"latency" json:"latency"`
	SpeedTest    SpeedTestConfig    `yaml:"speed_test" json:"speed_test"`
	Traffic      TrafficConfig      `yaml:"traffic" json:"traffic"`
	Connections  ConnectionsConfig  `yaml:"connections" json:"connections"`
	Destinations DestinationsConfig `yaml:"destinations" json:"destinations"`
	ThreatIntel  ThreatIntelConfig  `yaml:"threat_intel" json:"threat_intel"`
	Lateral      LateralConfig      `yaml:"lateral" json:"lateral"`
	PublicIP     PublicIPConfig     `yaml:"public_ip" json:"public_ip"`
	Routing      RoutingConfig      `yaml:"routing" json:"routing"`
	WiFi         WiFiConfig         `yaml:"wifi" json:"wifi"`
	Baseline     BaselineConfig     `yaml:"baseline" json:"baseline"`
	Alerts       AlertsConfig       `yaml:"alerts" json:"alerts"`
	Correlation  CorrelationConfig  `yaml:"correlation" json:"correlation"`
	Health       HealthConfig       `yaml:"health" json:"health"`
	Logging      LoggingConfig      `yaml:"logging" json:"logging"`
	Database     DatabaseConfig     `yaml:"database" json:"database"`
	Dashboard    DashboardConfig    `yaml:"dashboard" json:"dashboard"`
	Privacy      PrivacyConfig      `yaml:"privacy" json:"privacy"`

	// path records where this configuration was loaded from. Not settable from YAML.
	path string `yaml:"-" json:"-"`
}

// ServiceConfig covers process-level settings and filesystem layout.
type ServiceConfig struct {
	// DataDir holds the SQLite database and runtime state. Empty means the
	// platform default (/var/lib/ipulse, C:\ProgramData\iPulse\data).
	DataDir string `yaml:"data_dir" json:"data_dir"`
	// LogDir holds log files. Empty means the platform default
	// (/var/log/ipulse, C:\ProgramData\iPulse\logs).
	LogDir string `yaml:"log_dir" json:"log_dir"`
	// HostnameOverride replaces the detected hostname in records.
	HostnameOverride string `yaml:"hostname_override" json:"hostname_override"`
	// ShutdownTimeout bounds graceful shutdown before the process exits anyway.
	ShutdownTimeout Duration `yaml:"shutdown_timeout" json:"shutdown_timeout"`
	// StartupGrace delays the first heavy probe (full speed test) after start-up so
	// a boot-time storm of tests does not compete with the user's own traffic.
	StartupGrace Duration `yaml:"startup_grace" json:"startup_grace"`
}

// MonitoringConfig holds the scheduler intervals. Every interval is configurable.
type MonitoringConfig struct {
	HealthInterval        Duration `yaml:"health_interval" json:"health_interval"`
	DNSInterval           Duration `yaml:"dns_interval" json:"dns_interval"`
	LatencyInterval       Duration `yaml:"latency_interval" json:"latency_interval"`
	InterfaceInterval     Duration `yaml:"interface_interval" json:"interface_interval"`
	WiFiInterval          Duration `yaml:"wifi_interval" json:"wifi_interval"`
	PublicIPInterval      Duration `yaml:"public_ip_interval" json:"public_ip_interval"`
	RouteInterval         Duration `yaml:"route_interval" json:"route_interval"`
	TrafficInterval       Duration `yaml:"traffic_interval" json:"traffic_interval"`
	ConnectionInterval    Duration `yaml:"connection_interval" json:"connection_interval"`
	HealthScoreInterval   Duration `yaml:"health_score_interval" json:"health_score_interval"`
	BaselineFlushInterval Duration `yaml:"baseline_flush_interval" json:"baseline_flush_interval"`
	RetentionInterval     Duration `yaml:"retention_interval" json:"retention_interval"`
	AvailabilityInterval  Duration `yaml:"availability_report_interval" json:"availability_report_interval"`
	ThreatFeedInterval    Duration `yaml:"threat_feed_interval" json:"threat_feed_interval"`
	// ProbeTimeout bounds any single network probe.
	ProbeTimeout Duration `yaml:"probe_timeout" json:"probe_timeout"`
	// Jitter spreads scheduled tasks so they do not all fire on the same instant.
	Jitter Duration `yaml:"jitter" json:"jitter"`
}

// Target is a reachability probe target.
type Target struct {
	Name string `yaml:"name" json:"name"`
	// Type is tcp, https or icmp.
	Type string `yaml:"type" json:"type"`
	// Address is host:port for tcp, a URL for https, or an IP/hostname for icmp.
	Address string `yaml:"address" json:"address"`
	// Notes documents why the target was chosen (for example its network operator),
	// so an operator can tell whether the target set is diverse enough.
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// ConnectivityConfig defines the health-check and diagnostic ladder targets.
type ConnectivityConfig struct {
	// Targets are the fast, cheap health-check probes.
	Targets []Target `yaml:"targets" json:"targets"`
	// RequiredSuccess is how many targets must respond for the link to count as up.
	RequiredSuccess int `yaml:"required_success" json:"required_success"`
	// IPLiterals are external addresses probed without DNS, to separate name
	// resolution failures from path failures. Choose addresses in different networks.
	IPLiterals []string `yaml:"ip_literals" json:"ip_literals"`
	// HTTPSTargets verify that a full TLS session can be established.
	HTTPSTargets []string `yaml:"https_targets" json:"https_targets"`
	// FailuresBeforeOutage is how many consecutive failed health checks open an outage.
	FailuresBeforeOutage int `yaml:"failures_before_outage" json:"failures_before_outage"`
	// SuccessesBeforeRecovery is how many consecutive successes close an outage.
	SuccessesBeforeRecovery int `yaml:"successes_before_recovery" json:"successes_before_recovery"`
	// GatewayProbeMethod is auto, icmp or tcp.
	GatewayProbeMethod string `yaml:"gateway_probe_method" json:"gateway_probe_method"`
	// GatewayTCPPorts are tried when probing the gateway over TCP (routers usually
	// answer on at least one of these).
	GatewayTCPPorts []int `yaml:"gateway_tcp_ports" json:"gateway_tcp_ports"`
}

// DNSConfig configures the DNS monitor.
type DNSConfig struct {
	// Names resolved on each cycle. One is used per cycle, round-robin, to avoid
	// hammering a single name.
	Names []string `yaml:"names" json:"names"`
	// Servers to query directly. Empty means use the system resolvers.
	Servers []string `yaml:"servers" json:"servers"`
	// FallbackServers are queried only during diagnostics, to distinguish a broken
	// local resolver from a broken network.
	FallbackServers []string `yaml:"fallback_servers" json:"fallback_servers"`
	Timeout         Duration `yaml:"timeout" json:"timeout"`
	// SlowThreshold marks a response as slow.
	SlowThreshold Duration `yaml:"slow_threshold" json:"slow_threshold"`
	// UseSystemResolver queries through the OS resolver in addition to direct queries.
	UseSystemResolver bool `yaml:"use_system_resolver" json:"use_system_resolver"`
}

// LatencyConfig configures the latency and packet-loss monitor.
type LatencyConfig struct {
	Targets []string `yaml:"targets" json:"targets"`
	// Probes is the number of echoes per target per cycle; packet loss is derived
	// from this sample.
	Probes int `yaml:"probes" json:"probes"`
	// Spacing is the delay between probes within a cycle.
	Spacing Duration `yaml:"spacing" json:"spacing"`
	Timeout Duration `yaml:"timeout" json:"timeout"`
	// Method is auto, icmp or tcp. auto prefers ICMP and falls back to TCP connect
	// timing when ICMP sockets are not permitted.
	Method string `yaml:"method" json:"method"`
	// TCPPort is the port used by the TCP fallback.
	TCPPort int `yaml:"tcp_port" json:"tcp_port"`
	// IncludeGateway also measures the default gateway each cycle, which is what
	// separates local-network latency from Internet latency.
	IncludeGateway bool `yaml:"include_gateway" json:"include_gateway"`
}

// SpeedEndpoint is one speed-test endpoint. The {bytes} placeholder in DownloadURL is
// replaced with the requested transfer size.
type SpeedEndpoint struct {
	Name        string `yaml:"name" json:"name"`
	DownloadURL string `yaml:"download_url" json:"download_url"`
	UploadURL   string `yaml:"upload_url" json:"upload_url"`
	// LatencyURL is a tiny object used for TTFB/latency measurement. Optional;
	// DownloadURL with a small size is used when empty.
	LatencyURL string `yaml:"latency_url,omitempty" json:"latency_url,omitempty"`
	MaxStreams int    `yaml:"max_streams" json:"max_streams"`
	// Location documents where the endpoint is, for reporting.
	Location string `yaml:"location,omitempty" json:"location,omitempty"`
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// SpeedTestConfig configures the speed-test engine.
type SpeedTestConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Provider selects the registered provider implementation.
	Provider             string   `yaml:"provider" json:"provider"`
	LightweightInterval  Duration `yaml:"lightweight_interval" json:"lightweight_interval"`
	FullInterval         Duration `yaml:"full_interval" json:"full_interval"`
	ExpectedDownloadMbps float64  `yaml:"expected_download_mbps" json:"expected_download_mbps"`
	ExpectedUploadMbps   float64  `yaml:"expected_upload_mbps" json:"expected_upload_mbps"`

	// Streams is the number of parallel connections for the full test.
	Streams int `yaml:"streams" json:"streams"`
	// Warmup is discarded before measurement so TCP slow-start does not depress the
	// result.
	Warmup Duration `yaml:"warmup" json:"warmup"`
	// Duration bounds the download measurement window.
	Duration Duration `yaml:"duration" json:"duration"`
	// UploadDuration bounds the upload measurement window.
	UploadDuration Duration `yaml:"upload_duration" json:"upload_duration"`
	// MaxDownloadBytes and MaxUploadBytes cap the data a single test may transfer, so
	// a fast link cannot consume a metered allowance.
	MaxDownloadBytes int64 `yaml:"max_download_bytes" json:"max_download_bytes"`
	MaxUploadBytes   int64 `yaml:"max_upload_bytes" json:"max_upload_bytes"`
	// LightweightBytes is the transfer size for the cheap probe.
	LightweightBytes int64 `yaml:"lightweight_bytes" json:"lightweight_bytes"`
	// SkipIfBusyMbps skips a scheduled test when the link is already carrying more
	// than this rate, because the result would be meaningless and the test would
	// compete with real traffic. Zero disables the check.
	SkipIfBusyMbps float64 `yaml:"skip_if_busy_mbps" json:"skip_if_busy_mbps"`
	// EndpointSelection is latency (pick the lowest connect time), first or random.
	EndpointSelection string `yaml:"endpoint_selection" json:"endpoint_selection"`
	// Endpoints is the list of usable endpoints.
	Endpoints []SpeedEndpoint `yaml:"endpoints" json:"endpoints"`
	// UploadEnabled allows disabling upload measurement on metered links.
	UploadEnabled bool `yaml:"upload_enabled" json:"upload_enabled"`
	// Timeout bounds a whole speed test.
	Timeout Duration `yaml:"timeout" json:"timeout"`
}

// TrafficConfig configures interface counter sampling and traffic anomaly detection.
type TrafficConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Interfaces limits monitoring to these names. Empty means all non-loopback.
	Interfaces []string `yaml:"interfaces" json:"interfaces"`
	// ExcludeInterfaces skips these names (glob patterns allowed).
	ExcludeInterfaces []string `yaml:"exclude_interfaces" json:"exclude_interfaces"`
	// SpikeZScore is the robust z-score above which a rate counts as a spike.
	SpikeZScore float64 `yaml:"spike_z_score" json:"spike_z_score"`
	// SpikeMinMbps suppresses spike events below this absolute rate, so a quiet link
	// does not produce statistically-large but practically-irrelevant spikes.
	SpikeMinMbps float64 `yaml:"spike_min_mbps" json:"spike_min_mbps"`
	// SustainedSeconds is how long a rate must stay elevated to count as sustained.
	SustainedSeconds int `yaml:"sustained_seconds" json:"sustained_seconds"`
	// SustainedUploadMbps is the floor for the sustained-upload detector.
	SustainedUploadMbps float64 `yaml:"sustained_upload_mbps" json:"sustained_upload_mbps"`
	// LargeTransferMB triggers the large-outbound-transfer detector.
	LargeTransferMB float64 `yaml:"large_transfer_mb" json:"large_transfer_mb"`
	// QuietHoursStart/End bound the "unusual overnight activity" window (local time,
	// 24h clock). Start may be greater than End to wrap midnight.
	QuietHoursStart int `yaml:"quiet_hours_start" json:"quiet_hours_start"`
	QuietHoursEnd   int `yaml:"quiet_hours_end" json:"quiet_hours_end"`
	// ExcludeSelfTraffic attributes iPulse's own speed-test bytes to iPulse so its
	// tests never raise traffic anomalies.
	ExcludeSelfTraffic bool `yaml:"exclude_self_traffic" json:"exclude_self_traffic"`
	// ErrorRateThreshold is errors+drops per second that raises INTERFACE_ERRORS_RISING.
	ErrorRateThreshold float64 `yaml:"error_rate_threshold" json:"error_rate_threshold"`
}

// ConnectionsConfig configures active TCP/UDP connection collection.
type ConnectionsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IncludeUDP collects UDP sockets in addition to TCP.
	IncludeUDP bool `yaml:"include_udp" json:"include_udp"`
	// IncludeListening records listening sockets (useful context, more rows).
	IncludeListening bool `yaml:"include_listening" json:"include_listening"`
	// IncludeLoopback records loopback connections. Off by default: they are noisy
	// and rarely interesting for Internet observability.
	IncludeLoopback bool `yaml:"include_loopback" json:"include_loopback"`
	// ResolveProcess attributes sockets to processes. Needs elevation to see other
	// users' sockets.
	ResolveProcess bool `yaml:"resolve_process" json:"resolve_process"`
	// MaxConnectionsPerSample bounds work on very busy hosts.
	MaxConnectionsPerSample int `yaml:"max_connections_per_sample" json:"max_connections_per_sample"`
	// IdleTimeout closes a tracked connection record after this long without being
	// observed.
	IdleTimeout Duration `yaml:"idle_timeout" json:"idle_timeout"`
}

// DestinationsConfig configures destination history and novelty analysis.
type DestinationsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// NewDestinationWindow is how long a destination counts as new.
	NewDestinationWindow Duration `yaml:"new_destination_window" json:"new_destination_window"`
	// LearningPeriod suppresses new-destination events entirely for this long after
	// first start, while the initial picture is built.
	LearningPeriod Duration `yaml:"learning_period" json:"learning_period"`
	// RarePercentile marks destinations below this contact-frequency percentile rare.
	RarePercentile float64 `yaml:"rare_percentile" json:"rare_percentile"`
	// HighVolumeMB is the outbound volume that makes a new destination notable.
	HighVolumeMB float64 `yaml:"high_volume_mb" json:"high_volume_mb"`
	// FanoutWindow and FanoutThreshold detect rapid contact with many destinations.
	FanoutWindow    Duration `yaml:"fanout_window" json:"fanout_window"`
	FanoutThreshold int      `yaml:"fanout_threshold" json:"fanout_threshold"`
	// ExpectedPorts are ports considered normal for outbound traffic.
	ExpectedPorts []int `yaml:"expected_ports" json:"expected_ports"`
	// ReverseDNS enables reverse lookups for external destinations.
	ReverseDNS bool `yaml:"reverse_dns" json:"reverse_dns"`
	// Enrichment names optional enrichment providers to enable. Empty means none, so
	// no third-party service is contacted unless the operator opts in.
	Enrichment []string `yaml:"enrichment" json:"enrichment"`
	// EnrichmentURL is the template for the enabled network enrichment provider.
	EnrichmentURL string `yaml:"enrichment_url,omitempty" json:"enrichment_url,omitempty"`
	// IgnoreDestinations are CIDRs or hostnames never reported.
	IgnoreDestinations []string `yaml:"ignore_destinations" json:"ignore_destinations"`
	// IgnoreProcesses are process names whose destinations are never reported.
	IgnoreProcesses []string `yaml:"ignore_processes" json:"ignore_processes"`
}

// ThreatFeed is one threat-intelligence source.
type ThreatFeed struct {
	Name string `yaml:"name" json:"name"`
	// Type is ip, cidr, domain or ioc (mixed).
	Type string `yaml:"type" json:"type"`
	// Format is plain, csv, hosts, json or auto.
	Format string `yaml:"format" json:"format"`
	// URL or Path; exactly one must be set.
	URL  string `yaml:"url,omitempty" json:"url,omitempty"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Confidence is low, medium or high, applied to indicators from this feed.
	Confidence string `yaml:"confidence" json:"confidence"`
	// Column selects the indicator column for csv feeds (1-based).
	Column int `yaml:"column,omitempty" json:"column,omitempty"`
	// Field selects the indicator field for json feeds (dot path).
	Field   string `yaml:"field,omitempty" json:"field,omitempty"`
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// ThreatIntelConfig configures the local threat-intelligence store.
type ThreatIntelConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Feeds are imported on the threat_feed_interval. No feed is configured by
	// default: iPulse contacts no third party unless the operator adds one.
	Feeds []ThreatFeed `yaml:"feeds" json:"feeds"`
	// MaxIndicators bounds the local store.
	MaxIndicators int `yaml:"max_indicators" json:"max_indicators"`
	// ExpireAfter removes indicators not seen in a feed for this long.
	ExpireAfter Duration `yaml:"expire_after" json:"expire_after"`
	// MatchPrivate also matches indicators against private addresses.
	MatchPrivate bool `yaml:"match_private" json:"match_private"`
	// AllowList are indicators never matched (your own infrastructure).
	AllowList []string `yaml:"allow_list" json:"allow_list"`
}

// LateralConfig configures private-network scan heuristics.
type LateralConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Window is the sliding window over which internal connections are counted.
	Window Duration `yaml:"window" json:"window"`
	// HostSweepThreshold is the number of distinct internal hosts in the window that
	// raises a possible sweep.
	HostSweepThreshold int `yaml:"host_sweep_threshold" json:"host_sweep_threshold"`
	// PortScanThreshold is the number of distinct ports on one host that raises a
	// possible port scan.
	PortScanThreshold int `yaml:"port_scan_threshold" json:"port_scan_threshold"`
	// FailedConnectionThreshold is the number of failed internal attempts that raises
	// repeated-failure reporting.
	FailedConnectionThreshold int `yaml:"failed_connection_threshold" json:"failed_connection_threshold"`
	// AdminPorts are the remote-administration ports watched for sweeps.
	AdminPorts []int `yaml:"admin_ports" json:"admin_ports"`
	// AdminSweepHosts is the number of distinct hosts contacted on admin ports that
	// raises a sweep.
	AdminSweepHosts int `yaml:"admin_sweep_hosts" json:"admin_sweep_hosts"`
	// AllowProcesses are approved scanners/management tools that never raise events.
	AllowProcesses []string `yaml:"allow_processes" json:"allow_processes"`
	// ExtraPrivateRanges adds site-specific ranges that should count as internal.
	ExtraPrivateRanges []string `yaml:"extra_private_ranges" json:"extra_private_ranges"`
}

// PublicIPConfig configures public address discovery.
type PublicIPConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Providers are queried in order until one answers; the answer is cross-checked
	// against a second provider before a change is reported.
	Providers []string `yaml:"providers" json:"providers"`
	// IPv6Providers are the equivalents for IPv6. Empty disables IPv6 discovery.
	IPv6Providers []string `yaml:"ipv6_providers" json:"ipv6_providers"`
	Timeout       Duration `yaml:"timeout" json:"timeout"`
	// ConfirmChanges requires two providers to agree before a change is recorded,
	// which avoids spurious changes from a single misbehaving provider.
	ConfirmChanges bool `yaml:"confirm_changes" json:"confirm_changes"`
	// ASNLookup enables ASN/organisation enrichment for the public IP.
	ASNLookup bool `yaml:"asn_lookup" json:"asn_lookup"`
	// ASNProviderURL is the enrichment endpoint template ({ip} placeholder).
	ASNProviderURL string `yaml:"asn_provider_url,omitempty" json:"asn_provider_url,omitempty"`
}

// RoutingConfig configures path monitoring.
type RoutingConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Destinations are stable Internet endpoints whose path is tracked.
	Destinations []string `yaml:"destinations" json:"destinations"`
	MaxHops      int      `yaml:"max_hops" json:"max_hops"`
	// ProbesPerHop trades accuracy against traffic.
	ProbesPerHop int      `yaml:"probes_per_hop" json:"probes_per_hop"`
	Timeout      Duration `yaml:"timeout" json:"timeout"`
	// HopChangeTolerance is how many hops may differ before a route change is
	// reported, since ECMP causes benign hop variation.
	HopChangeTolerance int `yaml:"hop_change_tolerance" json:"hop_change_tolerance"`
}

// WiFiConfig configures wireless telemetry.
type WiFiConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// WeakSignalDBM is the RSSI at or below which the signal counts as weak.
	WeakSignalDBM int `yaml:"weak_signal_dbm" json:"weak_signal_dbm"`
	// LinkSpeedDegradePercent is the drop from baseline link rate that is reported.
	LinkSpeedDegradePercent float64 `yaml:"link_speed_degrade_percent" json:"link_speed_degrade_percent"`
}

// BaselineConfig configures the adaptive baseline engine.
type BaselineConfig struct {
	// MinObservations is how many samples a metric/bucket needs before detectors act.
	// This is the primary false-positive guard.
	MinObservations int `yaml:"min_observations" json:"min_observations"`
	// Window is how far back samples contribute to a baseline.
	Window Duration `yaml:"window" json:"window"`
	// TimeBuckets enables hour-of-day and weekday/weekend aware baselines.
	TimeBuckets bool `yaml:"time_buckets" json:"time_buckets"`
	// BucketHours is the width of an hour bucket (1 gives 24 buckets per day class).
	BucketHours int `yaml:"bucket_hours" json:"bucket_hours"`
	// EWMAAlpha weights recent samples in the exponentially-weighted summary.
	EWMAAlpha float64 `yaml:"ewma_alpha" json:"ewma_alpha"`
	// ReservoirSize bounds the per-bucket sample reservoir used for percentiles.
	ReservoirSize int `yaml:"reservoir_size" json:"reservoir_size"`
	// MaxSampleAge discards baseline buckets untouched for this long.
	MaxSampleAge Duration `yaml:"max_sample_age" json:"max_sample_age"`
}

// AlertsConfig holds the detector thresholds an operator is most likely to tune.
type AlertsConfig struct {
	DownloadDegradationPercent float64 `yaml:"download_degradation_percent" json:"download_degradation_percent"`
	UploadDegradationPercent   float64 `yaml:"upload_degradation_percent" json:"upload_degradation_percent"`
	LatencyDegradationPercent  float64 `yaml:"latency_degradation_percent" json:"latency_degradation_percent"`
	JitterDegradationPercent   float64 `yaml:"jitter_degradation_percent" json:"jitter_degradation_percent"`
	PacketLossPercent          float64 `yaml:"packet_loss_percent" json:"packet_loss_percent"`
	DNSDegradationPercent      float64 `yaml:"dns_degradation_percent" json:"dns_degradation_percent"`
	ISPShortfallPercent        float64 `yaml:"isp_shortfall_percent" json:"isp_shortfall_percent"`
	SustainedUploadSeconds     int     `yaml:"sustained_upload_seconds" json:"sustained_upload_seconds"`
	SustainedLatencySeconds    int     `yaml:"sustained_latency_seconds" json:"sustained_latency_seconds"`
	SustainedBandwidthSeconds  int     `yaml:"sustained_bandwidth_seconds" json:"sustained_bandwidth_seconds"`
	// Persistence is how many consecutive breaches are required before an event is
	// raised. Raising this trades detection latency for fewer false positives.
	Persistence int `yaml:"persistence" json:"persistence"`
	// RecoveryPersistence is the equivalent for clearing a degradation.
	RecoveryPersistence int `yaml:"recovery_persistence" json:"recovery_persistence"`
	// Cooldown suppresses repeats of the same event/dimension for this long.
	Cooldown Duration `yaml:"cooldown" json:"cooldown"`
	// MinAbsoluteLatencyMS suppresses latency deviation events when the absolute
	// value is still small (a 5 ms baseline going to 12 ms is a 140 % deviation but
	// is not a problem).
	MinAbsoluteLatencyMS float64 `yaml:"min_absolute_latency_ms" json:"min_absolute_latency_ms"`
	// MinAbsoluteMbps suppresses throughput degradation on already-slow links where
	// relative movement is noisy.
	MinAbsoluteMbps float64 `yaml:"min_absolute_mbps" json:"min_absolute_mbps"`
}

// CorrelationConfig configures the event-correlation engine.
type CorrelationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Window is how far back the engine looks for supporting signals.
	Window Duration `yaml:"window" json:"window"`
	// SuppressContributing hides the contributing raw events from the readable log
	// once a correlation rule explains them. They remain in the database.
	SuppressContributing bool `yaml:"suppress_contributing" json:"suppress_contributing"`
}

// HealthConfig configures the 0-100 Internet health score.
type HealthConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Weights must sum to a positive value; they are normalised at load time.
	Weights HealthWeights `yaml:"weights" json:"weights"`
	// Window is the period the score summarises.
	Window Duration `yaml:"window" json:"window"`
	// WarnBelow raises HEALTH_SCORE_DEGRADED when the score drops under it.
	WarnBelow float64 `yaml:"warn_below" json:"warn_below"`
	// LatencyGoodMS scores 100 at or below this value, LatencyBadMS scores 0.
	LatencyGoodMS float64 `yaml:"latency_good_ms" json:"latency_good_ms"`
	LatencyBadMS  float64 `yaml:"latency_bad_ms" json:"latency_bad_ms"`
	JitterGoodMS  float64 `yaml:"jitter_good_ms" json:"jitter_good_ms"`
	JitterBadMS   float64 `yaml:"jitter_bad_ms" json:"jitter_bad_ms"`
	LossGoodPct   float64 `yaml:"loss_good_percent" json:"loss_good_percent"`
	LossBadPct    float64 `yaml:"loss_bad_percent" json:"loss_bad_percent"`
	DNSGoodMS     float64 `yaml:"dns_good_ms" json:"dns_good_ms"`
	DNSBadMS      float64 `yaml:"dns_bad_ms" json:"dns_bad_ms"`
}

// HealthWeights are the relative contributions of each component to the score.
type HealthWeights struct {
	Availability float64 `yaml:"availability" json:"availability"`
	Download     float64 `yaml:"download" json:"download"`
	Upload       float64 `yaml:"upload" json:"upload"`
	Latency      float64 `yaml:"latency" json:"latency"`
	Jitter       float64 `yaml:"jitter" json:"jitter"`
	PacketLoss   float64 `yaml:"packet_loss" json:"packet_loss"`
	DNS          float64 `yaml:"dns" json:"dns"`
}

// LoggingConfig configures the logging engine and its sinks.
type LoggingConfig struct {
	// Level is the minimum severity written to the sinks.
	Level string `yaml:"level" json:"level"`
	// Text enables the human-readable .log sink.
	Text bool `yaml:"text" json:"text"`
	// JSON enables the JSON Lines sink.
	JSON bool `yaml:"json" json:"json"`
	// Database enables the searchable SQLite events table.
	Database bool `yaml:"database" json:"database"`
	// Syslog enables journald/syslog on Linux.
	Syslog bool `yaml:"syslog" json:"syslog"`
	// EventLog enables the Windows Event Log.
	EventLog bool `yaml:"eventlog" json:"eventlog"`
	// Console writes to stderr; useful in foreground and container mode.
	Console bool `yaml:"console" json:"console"`
	// SyslogSeverity is the minimum severity forwarded to the OS log, which is
	// usually higher than the file level to keep the system log readable.
	SyslogSeverity string `yaml:"syslog_severity" json:"syslog_severity"`
	// MaxFileMB triggers rotation.
	MaxFileMB int `yaml:"max_file_mb" json:"max_file_mb"`
	// MaxArchives is how many rotated files to keep per log.
	MaxArchives int `yaml:"max_archives" json:"max_archives"`
	// RetentionDays deletes archives older than this.
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
	// Compress gzips rotated archives.
	Compress bool `yaml:"compress" json:"compress"`
	// RotateDaily rotates at local midnight in addition to the size trigger.
	RotateDaily bool `yaml:"rotate_daily" json:"rotate_daily"`
	// FileMode is the octal permission for log files.
	FileMode string `yaml:"file_mode" json:"file_mode"`
}

// DatabaseConfig configures local storage.
type DatabaseConfig struct {
	// Path is the SQLite file. Empty means <data_dir>/ipulse.db.
	Path string `yaml:"path" json:"path"`
	// BusyTimeout is how long a writer waits for a lock.
	BusyTimeout Duration `yaml:"busy_timeout" json:"busy_timeout"`
	// Retention is per-table, in days.
	Retention RetentionConfig `yaml:"retention" json:"retention"`
	// MaxSizeMB logs a warning when exceeded and tightens pruning.
	MaxSizeMB int `yaml:"max_size_mb" json:"max_size_mb"`
	// VacuumInterval runs incremental vacuum after pruning.
	VacuumInterval Duration `yaml:"vacuum_interval" json:"vacuum_interval"`
	// Downsample rolls raw measurements into hourly aggregates before deletion so
	// long-range charts survive retention.
	Downsample bool `yaml:"downsample" json:"downsample"`
}

// RetentionConfig holds per-table retention in days.
type RetentionConfig struct {
	EventsDays       int `yaml:"events_days" json:"events_days"`
	MeasurementsDays int `yaml:"measurements_days" json:"measurements_days"`
	SpeedTestsDays   int `yaml:"speed_tests_days" json:"speed_tests_days"`
	OutagesDays      int `yaml:"outages_days" json:"outages_days"`
	ConnectionsDays  int `yaml:"connections_days" json:"connections_days"`
	DestinationsDays int `yaml:"destinations_days" json:"destinations_days"`
	TrafficDays      int `yaml:"traffic_days" json:"traffic_days"`
	AggregatesDays   int `yaml:"aggregates_days" json:"aggregates_days"`
}

// DashboardConfig configures the local API and web dashboard.
type DashboardConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Address is the bind address. It defaults to loopback and a warning is logged if
	// it is widened.
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	// AuthToken, when set, is required as a bearer token or X-iPulse-Token header.
	// Required if the bind address is not loopback.
	AuthToken string `yaml:"auth_token" json:"auth_token"`
	// AllowedHosts is the Host header allow-list that defeats DNS rebinding.
	AllowedHosts []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	// AllowRemoteTests permits POST test endpoints from non-loopback clients.
	AllowRemoteTests bool `yaml:"allow_remote_tests" json:"allow_remote_tests"`
	// ReadTimeout and WriteTimeout bound HTTP handling.
	ReadTimeout  Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout" json:"write_timeout"`
	// RateLimitPerMinute bounds expensive POST test requests per client.
	RateLimitPerMinute int `yaml:"rate_limit_per_minute" json:"rate_limit_per_minute"`
	// TLSCertFile and TLSKeyFile enable HTTPS. Optional; loopback HTTP is the default.
	TLSCertFile string `yaml:"tls_cert_file,omitempty" json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `yaml:"tls_key_file,omitempty" json:"tls_key_file,omitempty"`
}

// PrivacyConfig makes the privacy posture explicit and auditable in configuration.
type PrivacyConfig struct {
	// CollectProcessNames records the process owning a connection.
	CollectProcessNames bool `yaml:"collect_process_names" json:"collect_process_names"`
	// CollectExecutablePaths records full executable paths.
	CollectExecutablePaths bool `yaml:"collect_executable_paths" json:"collect_executable_paths"`
	// CollectUsernames records the account owning a socket.
	CollectUsernames bool `yaml:"collect_usernames" json:"collect_usernames"`
	// CollectRemoteHostnames performs reverse DNS on remote addresses.
	CollectRemoteHostnames bool `yaml:"collect_remote_hostnames" json:"collect_remote_hostnames"`
	// AnonymizeLocalAddresses masks the host portion of local addresses in logs.
	AnonymizeLocalAddresses bool `yaml:"anonymize_local_addresses" json:"anonymize_local_addresses"`
	// PayloadInspection is reserved and must remain false: iPulse performs no payload
	// capture and no TLS interception. Setting it true is rejected by validation.
	PayloadInspection bool `yaml:"payload_inspection" json:"payload_inspection"`
}

// Path returns the file this configuration was loaded from, if any.
func (c *Config) Path() string { return c.path }

// SetPath records the origin of the configuration.
func (c *Config) SetPath(p string) { c.path = p }
