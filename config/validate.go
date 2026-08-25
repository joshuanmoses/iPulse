package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/events"
)

// ValidationError aggregates every problem found in a configuration, so an operator
// sees all mistakes at once instead of fixing them one restart at a time.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid configuration: " + e.Problems[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration (%d problems):", len(e.Problems))
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}

type problems struct{ list []string }

func (p *problems) addf(format string, args ...any) {
	p.list = append(p.list, fmt.Sprintf(format, args...))
}

// Validate normalises and checks the configuration. It returns non-fatal warnings and,
// if the configuration cannot safely be applied, a *ValidationError describing every
// problem. Validation always runs before a configuration is applied.
func (c *Config) Validate() (warnings []string, err error) {
	var p problems
	var w []string

	c.Normalize()

	// ---- intervals -------------------------------------------------------------
	type iv struct {
		name string
		val  Duration
		min  time.Duration
	}
	for _, i := range []iv{
		{"monitoring.health_interval", c.Monitoring.HealthInterval, time.Second},
		{"monitoring.dns_interval", c.Monitoring.DNSInterval, time.Second},
		{"monitoring.latency_interval", c.Monitoring.LatencyInterval, time.Second},
		{"monitoring.interface_interval", c.Monitoring.InterfaceInterval, time.Second},
		{"monitoring.wifi_interval", c.Monitoring.WiFiInterval, time.Second},
		{"monitoring.public_ip_interval", c.Monitoring.PublicIPInterval, 30 * time.Second},
		{"monitoring.route_interval", c.Monitoring.RouteInterval, time.Minute},
		{"monitoring.traffic_interval", c.Monitoring.TrafficInterval, time.Second},
		{"monitoring.connection_interval", c.Monitoring.ConnectionInterval, time.Second},
		{"monitoring.health_score_interval", c.Monitoring.HealthScoreInterval, 10 * time.Second},
		{"monitoring.baseline_flush_interval", c.Monitoring.BaselineFlushInterval, 10 * time.Second},
		{"monitoring.retention_interval", c.Monitoring.RetentionInterval, time.Minute},
		{"monitoring.availability_report_interval", c.Monitoring.AvailabilityInterval, time.Minute},
		{"monitoring.threat_feed_interval", c.Monitoring.ThreatFeedInterval, time.Minute},
		{"monitoring.probe_timeout", c.Monitoring.ProbeTimeout, 250 * time.Millisecond},
		{"speed_test.lightweight_interval", c.SpeedTest.LightweightInterval, 30 * time.Second},
		{"speed_test.full_interval", c.SpeedTest.FullInterval, time.Minute},
		{"speed_test.duration", c.SpeedTest.Duration, time.Second},
		{"speed_test.upload_duration", c.SpeedTest.UploadDuration, time.Second},
		{"speed_test.timeout", c.SpeedTest.Timeout, 5 * time.Second},
		{"dns.timeout", c.DNS.Timeout, 100 * time.Millisecond},
		{"latency.timeout", c.Latency.Timeout, 100 * time.Millisecond},
		{"public_ip.timeout", c.PublicIP.Timeout, time.Second},
		{"routing.timeout", c.Routing.Timeout, time.Second},
		{"baseline.window", c.Baseline.Window, time.Hour},
		{"correlation.window", c.Correlation.Window, 10 * time.Second},
		{"health.window", c.Health.Window, time.Minute},
		{"database.busy_timeout", c.Database.BusyTimeout, 100 * time.Millisecond},
		{"dashboard.read_timeout", c.Dashboard.ReadTimeout, time.Second},
		{"dashboard.write_timeout", c.Dashboard.WriteTimeout, time.Second},
		{"service.shutdown_timeout", c.Service.ShutdownTimeout, time.Second},
	} {
		if i.val.D() < i.min {
			p.addf("%s must be at least %s (got %s)", i.name, i.min, i.val)
		}
	}
	if c.Monitoring.Jitter.D() < 0 {
		p.addf("monitoring.jitter must not be negative")
	}
	if c.Monitoring.ProbeTimeout.D() >= c.Monitoring.HealthInterval.D() {
		w = append(w, fmt.Sprintf("monitoring.probe_timeout (%s) is not shorter than health_interval (%s); health checks may overlap and be skipped",
			c.Monitoring.ProbeTimeout, c.Monitoring.HealthInterval))
	}
	if c.SpeedTest.Enabled && c.SpeedTest.FullInterval.D() < 5*time.Minute {
		w = append(w, fmt.Sprintf("speed_test.full_interval is %s; frequent full tests consume real bandwidth", c.SpeedTest.FullInterval))
	}

	// ---- connectivity ----------------------------------------------------------
	if len(c.Connectivity.Targets) == 0 {
		p.addf("connectivity.targets must not be empty")
	}
	seenTarget := map[string]bool{}
	for i, t := range c.Connectivity.Targets {
		where := fmt.Sprintf("connectivity.targets[%d]", i)
		if t.Name == "" {
			p.addf("%s.name is required", where)
		} else if seenTarget[t.Name] {
			p.addf("%s.name %q is duplicated", where, t.Name)
		}
		seenTarget[t.Name] = true
		switch strings.ToLower(t.Type) {
		case "tcp":
			if err := validateHostPort(t.Address); err != nil {
				p.addf("%s.address %q: %v", where, t.Address, err)
			}
		case "https", "http":
			if err := validateURL(t.Address); err != nil {
				p.addf("%s.address %q: %v", where, t.Address, err)
			}
		case "icmp":
			if err := validateHost(t.Address); err != nil {
				p.addf("%s.address %q: %v", where, t.Address, err)
			}
		default:
			p.addf("%s.type %q must be tcp, https or icmp", where, t.Type)
		}
	}
	if c.Connectivity.RequiredSuccess < 1 {
		p.addf("connectivity.required_success must be at least 1")
	}
	if n := len(c.Connectivity.Targets); n > 0 && c.Connectivity.RequiredSuccess > n {
		p.addf("connectivity.required_success (%d) exceeds the number of targets (%d)", c.Connectivity.RequiredSuccess, n)
	}
	if len(c.Connectivity.IPLiterals) == 0 {
		p.addf("connectivity.ip_literals must not be empty: diagnostics need DNS-free targets to separate name resolution from path failures")
	}
	for i, s := range c.Connectivity.IPLiterals {
		if _, err := netip.ParseAddr(s); err != nil {
			p.addf("connectivity.ip_literals[%d] %q is not an IP address", i, s)
		}
	}
	for i, s := range c.Connectivity.HTTPSTargets {
		if err := validateURL(s); err != nil {
			p.addf("connectivity.https_targets[%d] %q: %v", i, s, err)
		}
	}
	if c.Connectivity.FailuresBeforeOutage < 1 {
		p.addf("connectivity.failures_before_outage must be at least 1")
	}
	if c.Connectivity.SuccessesBeforeRecovery < 1 {
		p.addf("connectivity.successes_before_recovery must be at least 1")
	}
	switch strings.ToLower(c.Connectivity.GatewayProbeMethod) {
	case "auto", "icmp", "tcp":
	default:
		p.addf("connectivity.gateway_probe_method %q must be auto, icmp or tcp", c.Connectivity.GatewayProbeMethod)
	}
	for i, port := range c.Connectivity.GatewayTCPPorts {
		if port < 1 || port > 65535 {
			p.addf("connectivity.gateway_tcp_ports[%d] %d is not a valid port", i, port)
		}
	}

	// ---- dns -------------------------------------------------------------------
	if len(c.DNS.Names) == 0 {
		p.addf("dns.names must not be empty")
	}
	for i, n := range c.DNS.Names {
		if err := validateDomain(n); err != nil {
			p.addf("dns.names[%d] %q: %v", i, n, err)
		}
	}
	for i, s := range c.DNS.Servers {
		if err := validateHostPort(s); err != nil {
			p.addf("dns.servers[%d] %q: %v", i, s, err)
		}
	}
	for i, s := range c.DNS.FallbackServers {
		if err := validateHostPort(s); err != nil {
			p.addf("dns.fallback_servers[%d] %q: %v", i, s, err)
		}
	}
	if len(c.DNS.Servers) == 0 && !c.DNS.UseSystemResolver {
		p.addf("dns: either dns.servers must be set or dns.use_system_resolver must be true")
	}

	// ---- latency ---------------------------------------------------------------
	if len(c.Latency.Targets) == 0 {
		p.addf("latency.targets must not be empty")
	}
	for i, t := range c.Latency.Targets {
		if err := validateHost(t); err != nil {
			p.addf("latency.targets[%d] %q: %v", i, t, err)
		}
	}
	if c.Latency.Probes < 1 || c.Latency.Probes > 100 {
		p.addf("latency.probes must be between 1 and 100 (got %d)", c.Latency.Probes)
	}
	if c.Latency.Probes < 4 {
		w = append(w, fmt.Sprintf("latency.probes is %d; packet-loss percentages from fewer than 4 probes are very coarse", c.Latency.Probes))
	}
	switch strings.ToLower(c.Latency.Method) {
	case "auto", "icmp", "tcp":
	default:
		p.addf("latency.method %q must be auto, icmp or tcp", c.Latency.Method)
	}
	if c.Latency.TCPPort < 1 || c.Latency.TCPPort > 65535 {
		p.addf("latency.tcp_port %d is not a valid port", c.Latency.TCPPort)
	}
	if cycle := time.Duration(c.Latency.Probes) * (c.Latency.Spacing.D() + c.Latency.Timeout.D()); cycle > c.Monitoring.LatencyInterval.D() {
		w = append(w, fmt.Sprintf("latency probe cycle can take up to %s, longer than latency_interval (%s)", cycle, c.Monitoring.LatencyInterval))
	}

	// ---- speed test ------------------------------------------------------------
	if c.SpeedTest.Enabled {
		if c.SpeedTest.Provider == "" {
			p.addf("speed_test.provider must be set")
		}
		if c.SpeedTest.Streams < 1 || c.SpeedTest.Streams > 32 {
			p.addf("speed_test.streams must be between 1 and 32 (got %d)", c.SpeedTest.Streams)
		}
		if c.SpeedTest.MaxDownloadBytes < 1<<20 {
			p.addf("speed_test.max_download_bytes must be at least 1048576")
		}
		if c.SpeedTest.UploadEnabled && c.SpeedTest.MaxUploadBytes < 1<<19 {
			p.addf("speed_test.max_upload_bytes must be at least 524288 when upload is enabled")
		}
		if c.SpeedTest.LightweightBytes < 1<<16 {
			p.addf("speed_test.lightweight_bytes must be at least 65536")
		}
		if c.SpeedTest.Warmup.D() < 0 {
			p.addf("speed_test.warmup must not be negative")
		}
		if c.SpeedTest.Warmup.D() >= c.SpeedTest.Duration.D() {
			p.addf("speed_test.warmup (%s) must be shorter than speed_test.duration (%s)", c.SpeedTest.Warmup, c.SpeedTest.Duration)
		}
		if c.SpeedTest.ExpectedDownloadMbps < 0 || c.SpeedTest.ExpectedUploadMbps < 0 {
			p.addf("speed_test.expected_*_mbps must not be negative")
		}
		if c.SpeedTest.ExpectedDownloadMbps == 0 {
			w = append(w, "speed_test.expected_download_mbps is unset; iPulse cannot report shortfall against your ISP plan until you set it")
		}
		if c.SpeedTest.SkipIfBusyMbps < 0 {
			p.addf("speed_test.skip_if_busy_mbps must not be negative")
		}
		switch strings.ToLower(c.SpeedTest.EndpointSelection) {
		case "latency", "first", "random":
		default:
			p.addf("speed_test.endpoint_selection %q must be latency, first or random", c.SpeedTest.EndpointSelection)
		}
		enabled, uploadCapable := 0, 0
		names := map[string]bool{}
		for i, e := range c.SpeedTest.Endpoints {
			where := fmt.Sprintf("speed_test.endpoints[%d]", i)
			if e.Name == "" {
				p.addf("%s.name is required", where)
			} else if names[e.Name] {
				p.addf("%s.name %q is duplicated", where, e.Name)
			}
			names[e.Name] = true
			if err := validateURL(e.DownloadURL); err != nil {
				p.addf("%s.download_url %q: %v", where, e.DownloadURL, err)
			}
			if e.UploadURL != "" {
				if err := validateURL(e.UploadURL); err != nil {
					p.addf("%s.upload_url %q: %v", where, e.UploadURL, err)
				}
			}
			if e.LatencyURL != "" {
				if err := validateURL(e.LatencyURL); err != nil {
					p.addf("%s.latency_url %q: %v", where, e.LatencyURL, err)
				}
			}
			if e.MaxStreams < 0 || e.MaxStreams > 64 {
				p.addf("%s.max_streams must be between 0 and 64", where)
			}
			if e.Enabled == nil || *e.Enabled {
				enabled++
				if e.UploadURL != "" {
					uploadCapable++
				}
			}
		}
		if enabled == 0 {
			p.addf("speed_test.endpoints must contain at least one enabled endpoint while speed_test.enabled is true")
		}
		if c.SpeedTest.UploadEnabled && enabled > 0 && uploadCapable == 0 {
			w = append(w, "speed_test.upload_enabled is true but no enabled endpoint defines upload_url; upload will not be measured")
		}
	}

	// ---- traffic / connections -------------------------------------------------
	if c.Traffic.SpikeZScore < 1 {
		p.addf("traffic.spike_z_score must be at least 1 (got %v)", c.Traffic.SpikeZScore)
	}
	if c.Traffic.SpikeZScore < 3 {
		w = append(w, fmt.Sprintf("traffic.spike_z_score is %v; values below 3 produce many false spikes", c.Traffic.SpikeZScore))
	}
	if c.Traffic.SpikeMinMbps < 0 || c.Traffic.SustainedUploadMbps < 0 || c.Traffic.LargeTransferMB < 0 {
		p.addf("traffic thresholds must not be negative")
	}
	if c.Traffic.SustainedSeconds < 1 {
		p.addf("traffic.sustained_seconds must be at least 1")
	}
	if c.Traffic.QuietHoursStart < 0 || c.Traffic.QuietHoursStart > 23 {
		p.addf("traffic.quiet_hours_start must be 0-23")
	}
	if c.Traffic.QuietHoursEnd < 0 || c.Traffic.QuietHoursEnd > 23 {
		p.addf("traffic.quiet_hours_end must be 0-23")
	}
	if c.Traffic.ErrorRateThreshold < 0 {
		p.addf("traffic.error_rate_threshold must not be negative")
	}
	if c.Connections.MaxConnectionsPerSample < 16 {
		p.addf("connections.max_connections_per_sample must be at least 16")
	}
	if c.Connections.IdleTimeout.D() < time.Second {
		p.addf("connections.idle_timeout must be at least 1s")
	}

	// ---- destinations ----------------------------------------------------------
	if c.Destinations.RarePercentile < 0 || c.Destinations.RarePercentile > 50 {
		p.addf("destinations.rare_percentile must be between 0 and 50")
	}
	if c.Destinations.HighVolumeMB < 0 {
		p.addf("destinations.high_volume_mb must not be negative")
	}
	if c.Destinations.FanoutThreshold < 1 {
		p.addf("destinations.fanout_threshold must be at least 1")
	}
	if c.Destinations.FanoutWindow.D() < time.Second {
		p.addf("destinations.fanout_window must be at least 1s")
	}
	for i, port := range c.Destinations.ExpectedPorts {
		if port < 1 || port > 65535 {
			p.addf("destinations.expected_ports[%d] %d is not a valid port", i, port)
		}
	}
	for i, d := range c.Destinations.IgnoreDestinations {
		if err := validateHostOrCIDR(d); err != nil {
			p.addf("destinations.ignore_destinations[%d] %q: %v", i, d, err)
		}
	}
	if c.Destinations.EnrichmentURL != "" {
		if err := validateURL(c.Destinations.EnrichmentURL); err != nil {
			p.addf("destinations.enrichment_url: %v", err)
		}
		if !strings.Contains(c.Destinations.EnrichmentURL, "{ip}") {
			p.addf("destinations.enrichment_url must contain the {ip} placeholder")
		}
	}
	if len(c.Destinations.Enrichment) > 0 {
		w = append(w, fmt.Sprintf("destinations.enrichment enables external lookups (%s); iPulse will contact those services", strings.Join(c.Destinations.Enrichment, ", ")))
	}

	// ---- threat intel ----------------------------------------------------------
	if c.ThreatIntel.MaxIndicators < 1000 {
		p.addf("threat_intel.max_indicators must be at least 1000")
	}
	feedNames := map[string]bool{}
	for i, f := range c.ThreatIntel.Feeds {
		where := fmt.Sprintf("threat_intel.feeds[%d]", i)
		if f.Name == "" {
			p.addf("%s.name is required", where)
		} else if feedNames[f.Name] {
			p.addf("%s.name %q is duplicated", where, f.Name)
		}
		feedNames[f.Name] = true
		switch strings.ToLower(f.Type) {
		case "ip", "cidr", "domain", "ioc", "":
		default:
			p.addf("%s.type %q must be ip, cidr, domain or ioc", where, f.Type)
		}
		switch strings.ToLower(f.Format) {
		case "plain", "csv", "hosts", "json", "auto", "":
		default:
			p.addf("%s.format %q must be plain, csv, hosts, json or auto", where, f.Format)
		}
		switch {
		case f.URL == "" && f.Path == "":
			p.addf("%s: one of url or path is required", where)
		case f.URL != "" && f.Path != "":
			p.addf("%s: url and path are mutually exclusive", where)
		case f.URL != "":
			if err := validateURL(f.URL); err != nil {
				p.addf("%s.url %q: %v", where, f.URL, err)
			}
		}
		switch strings.ToLower(f.Confidence) {
		case "low", "medium", "high", "":
		default:
			p.addf("%s.confidence %q must be low, medium or high", where, f.Confidence)
		}
		if f.Column < 0 {
			p.addf("%s.column must not be negative", where)
		}
	}
	for i, a := range c.ThreatIntel.AllowList {
		if err := validateHostOrCIDR(a); err != nil {
			p.addf("threat_intel.allow_list[%d] %q: %v", i, a, err)
		}
	}

	// ---- lateral ---------------------------------------------------------------
	if c.Lateral.Window.D() < 10*time.Second {
		p.addf("lateral.window must be at least 10s")
	}
	if c.Lateral.HostSweepThreshold < 2 {
		p.addf("lateral.host_sweep_threshold must be at least 2")
	}
	if c.Lateral.PortScanThreshold < 2 {
		p.addf("lateral.port_scan_threshold must be at least 2")
	}
	if c.Lateral.FailedConnectionThreshold < 2 {
		p.addf("lateral.failed_connection_threshold must be at least 2")
	}
	if c.Lateral.AdminSweepHosts < 2 {
		p.addf("lateral.admin_sweep_hosts must be at least 2")
	}
	for i, port := range c.Lateral.AdminPorts {
		if port < 1 || port > 65535 {
			p.addf("lateral.admin_ports[%d] %d is not a valid port", i, port)
		}
	}
	for i, r := range c.Lateral.ExtraPrivateRanges {
		if _, err := netip.ParsePrefix(r); err != nil {
			p.addf("lateral.extra_private_ranges[%d] %q must be a CIDR prefix", i, r)
		}
	}

	// ---- public ip / routing / wifi -------------------------------------------
	if c.PublicIP.Enabled && len(c.PublicIP.Providers) == 0 {
		p.addf("public_ip.providers must not be empty while public_ip.enabled is true")
	}
	for i, u := range c.PublicIP.Providers {
		if err := validateURL(u); err != nil {
			p.addf("public_ip.providers[%d] %q: %v", i, u, err)
		}
	}
	for i, u := range c.PublicIP.IPv6Providers {
		if err := validateURL(u); err != nil {
			p.addf("public_ip.ipv6_providers[%d] %q: %v", i, u, err)
		}
	}
	if c.PublicIP.ConfirmChanges && len(c.PublicIP.Providers) < 2 {
		w = append(w, "public_ip.confirm_changes needs at least two providers to cross-check; changes will be accepted from a single provider")
	}
	if c.PublicIP.ASNProviderURL != "" {
		if err := validateURL(c.PublicIP.ASNProviderURL); err != nil {
			p.addf("public_ip.asn_provider_url: %v", err)
		} else if !strings.Contains(c.PublicIP.ASNProviderURL, "{ip}") {
			p.addf("public_ip.asn_provider_url must contain the {ip} placeholder")
		}
	}
	if c.Routing.Enabled {
		if len(c.Routing.Destinations) == 0 {
			p.addf("routing.destinations must not be empty while routing.enabled is true")
		}
		for i, d := range c.Routing.Destinations {
			if err := validateHost(d); err != nil {
				p.addf("routing.destinations[%d] %q: %v", i, d, err)
			}
		}
		if c.Routing.MaxHops < 1 || c.Routing.MaxHops > 64 {
			p.addf("routing.max_hops must be between 1 and 64")
		}
		if c.Routing.ProbesPerHop < 1 || c.Routing.ProbesPerHop > 5 {
			p.addf("routing.probes_per_hop must be between 1 and 5")
		}
		if c.Routing.HopChangeTolerance < 0 {
			p.addf("routing.hop_change_tolerance must not be negative")
		}
	}
	if c.WiFi.WeakSignalDBM > 0 || c.WiFi.WeakSignalDBM < -100 {
		p.addf("wifi.weak_signal_dbm must be between -100 and 0 (RSSI in dBm)")
	}
	if c.WiFi.LinkSpeedDegradePercent < 0 || c.WiFi.LinkSpeedDegradePercent > 100 {
		p.addf("wifi.link_speed_degrade_percent must be between 0 and 100")
	}

	// ---- baseline / alerts / correlation --------------------------------------
	if c.Baseline.MinObservations < 5 {
		p.addf("baseline.min_observations must be at least 5; lower values produce unreliable detection")
	}
	if c.Baseline.BucketHours < 1 || c.Baseline.BucketHours > 24 || 24%c.Baseline.BucketHours != 0 {
		p.addf("baseline.bucket_hours must be 1, 2, 3, 4, 6, 8, 12 or 24 (got %d)", c.Baseline.BucketHours)
	}
	if c.Baseline.EWMAAlpha <= 0 || c.Baseline.EWMAAlpha > 1 {
		p.addf("baseline.ewma_alpha must be greater than 0 and at most 1")
	}
	if c.Baseline.ReservoirSize < 16 || c.Baseline.ReservoirSize > 100000 {
		p.addf("baseline.reservoir_size must be between 16 and 100000")
	}
	if c.Baseline.MaxSampleAge.D() < c.Baseline.Window.D() {
		p.addf("baseline.max_sample_age (%s) must be at least baseline.window (%s)", c.Baseline.MaxSampleAge, c.Baseline.Window)
	}
	for name, v := range map[string]float64{
		"alerts.download_degradation_percent": c.Alerts.DownloadDegradationPercent,
		"alerts.upload_degradation_percent":   c.Alerts.UploadDegradationPercent,
		"alerts.latency_degradation_percent":  c.Alerts.LatencyDegradationPercent,
		"alerts.jitter_degradation_percent":   c.Alerts.JitterDegradationPercent,
		"alerts.dns_degradation_percent":      c.Alerts.DNSDegradationPercent,
		"alerts.isp_shortfall_percent":        c.Alerts.ISPShortfallPercent,
		"alerts.min_absolute_latency_ms":      c.Alerts.MinAbsoluteLatencyMS,
		"alerts.min_absolute_mbps":            c.Alerts.MinAbsoluteMbps,
	} {
		if v < 0 {
			p.addf("%s must not be negative", name)
		}
	}
	if c.Alerts.DownloadDegradationPercent > 100 || c.Alerts.UploadDegradationPercent > 100 || c.Alerts.ISPShortfallPercent > 100 {
		p.addf("alerts degradation/shortfall percentages relative to a baseline cannot exceed 100")
	}
	if c.Alerts.PacketLossPercent < 0 || c.Alerts.PacketLossPercent > 100 {
		p.addf("alerts.packet_loss_percent must be between 0 and 100")
	}
	if c.Alerts.Persistence < 1 {
		p.addf("alerts.persistence must be at least 1")
	}
	if c.Alerts.RecoveryPersistence < 1 {
		p.addf("alerts.recovery_persistence must be at least 1")
	}
	if c.Alerts.Cooldown.D() < 0 {
		p.addf("alerts.cooldown must not be negative")
	}
	if c.Alerts.SustainedUploadSeconds < 1 || c.Alerts.SustainedLatencySeconds < 1 || c.Alerts.SustainedBandwidthSeconds < 1 {
		p.addf("alerts.sustained_*_seconds must be at least 1")
	}

	// ---- health ----------------------------------------------------------------
	if c.Health.Enabled {
		wsum := c.Health.Weights.Availability + c.Health.Weights.Download + c.Health.Weights.Upload +
			c.Health.Weights.Latency + c.Health.Weights.Jitter + c.Health.Weights.PacketLoss + c.Health.Weights.DNS
		if wsum <= 0 {
			p.addf("health.weights must sum to a positive value")
		}
		for name, v := range map[string]float64{
			"health.weights.availability": c.Health.Weights.Availability,
			"health.weights.download":     c.Health.Weights.Download,
			"health.weights.upload":       c.Health.Weights.Upload,
			"health.weights.latency":      c.Health.Weights.Latency,
			"health.weights.jitter":       c.Health.Weights.Jitter,
			"health.weights.packet_loss":  c.Health.Weights.PacketLoss,
			"health.weights.dns":          c.Health.Weights.DNS,
		} {
			if v < 0 {
				p.addf("%s must not be negative", name)
			}
		}
		for _, pair := range []struct {
			good, bad         float64
			goodName, badName string
		}{
			{c.Health.LatencyGoodMS, c.Health.LatencyBadMS, "health.latency_good_ms", "health.latency_bad_ms"},
			{c.Health.JitterGoodMS, c.Health.JitterBadMS, "health.jitter_good_ms", "health.jitter_bad_ms"},
			{c.Health.LossGoodPct, c.Health.LossBadPct, "health.loss_good_percent", "health.loss_bad_percent"},
			{c.Health.DNSGoodMS, c.Health.DNSBadMS, "health.dns_good_ms", "health.dns_bad_ms"},
		} {
			if pair.good >= pair.bad {
				p.addf("%s (%v) must be less than %s (%v)", pair.goodName, pair.good, pair.badName, pair.bad)
			}
			if pair.good < 0 {
				p.addf("%s must not be negative", pair.goodName)
			}
		}
		if c.Health.WarnBelow < 0 || c.Health.WarnBelow > 100 {
			p.addf("health.warn_below must be between 0 and 100")
		}
	}

	// ---- logging ---------------------------------------------------------------
	if _, err := events.ParseSeverity(c.Logging.Level); err != nil {
		p.addf("logging.level %q must be one of debug, info, notice, warning, error, critical", c.Logging.Level)
	}
	if _, err := events.ParseSeverity(c.Logging.SyslogSeverity); err != nil {
		p.addf("logging.syslog_severity %q must be one of debug, info, notice, warning, error, critical", c.Logging.SyslogSeverity)
	}
	if !c.Logging.Text && !c.Logging.JSON && !c.Logging.Database && !c.Logging.Syslog && !c.Logging.EventLog && !c.Logging.Console {
		p.addf("logging: at least one sink must be enabled")
	}
	if c.Logging.MaxFileMB < 1 || c.Logging.MaxFileMB > 10240 {
		p.addf("logging.max_file_mb must be between 1 and 10240")
	}
	if c.Logging.MaxArchives < 0 || c.Logging.MaxArchives > 1000 {
		p.addf("logging.max_archives must be between 0 and 1000")
	}
	if c.Logging.RetentionDays < 1 {
		p.addf("logging.retention_days must be at least 1")
	}
	if mode, err := strconv.ParseUint(c.Logging.FileMode, 8, 32); err != nil {
		p.addf("logging.file_mode %q must be an octal permission such as 0640", c.Logging.FileMode)
	} else if mode&0o022 != 0 {
		p.addf("logging.file_mode %q grants write permission to group or other, which is unsafe for log files", c.Logging.FileMode)
	} else if mode&0o004 != 0 {
		w = append(w, fmt.Sprintf("logging.file_mode %q makes logs world-readable; connection metadata will be visible to every local user", c.Logging.FileMode))
	}
	if c.Logging.Level == "debug" {
		w = append(w, "logging.level is debug; expect high log volume and faster disk usage")
	}

	// ---- database --------------------------------------------------------------
	r := c.Database.Retention
	for name, days := range map[string]int{
		"events_days": r.EventsDays, "measurements_days": r.MeasurementsDays,
		"speed_tests_days": r.SpeedTestsDays, "outages_days": r.OutagesDays,
		"connections_days": r.ConnectionsDays, "destinations_days": r.DestinationsDays,
		"traffic_days": r.TrafficDays, "aggregates_days": r.AggregatesDays,
	} {
		if days < 1 {
			p.addf("database.retention.%s must be at least 1", name)
		}
	}
	if c.Database.MaxSizeMB < 0 {
		p.addf("database.max_size_mb must not be negative")
	}
	if c.Database.Path != "" && !isAbsPath(c.Database.Path) {
		w = append(w, fmt.Sprintf("database.path %q is relative; it will resolve against the service working directory", c.Database.Path))
	}

	// ---- dashboard / api -------------------------------------------------------
	if c.Dashboard.Enabled {
		if c.Dashboard.Port < 1 || c.Dashboard.Port > 65535 {
			p.addf("dashboard.port %d is not a valid port", c.Dashboard.Port)
		}
		addr, aerr := netip.ParseAddr(c.Dashboard.Address)
		if aerr != nil {
			p.addf("dashboard.address %q must be an IP address (use 127.0.0.1 for loopback only)", c.Dashboard.Address)
		} else if !addr.IsLoopback() {
			// Secure default: exposing the API off-host requires authentication.
			if c.Dashboard.AuthToken == "" {
				p.addf("dashboard.address %q is not a loopback address, so dashboard.auth_token is required", c.Dashboard.Address)
			}
			w = append(w, fmt.Sprintf("dashboard.address %q exposes the API beyond this host; ensure a firewall and TLS are in place", c.Dashboard.Address))
			if c.Dashboard.TLSCertFile == "" {
				w = append(w, "dashboard is bound to a non-loopback address without TLS; credentials and telemetry will cross the network in clear text")
			}
		}
		if c.Dashboard.AuthToken != "" && len(c.Dashboard.AuthToken) < 16 {
			p.addf("dashboard.auth_token must be at least 16 characters")
		}
		if (c.Dashboard.TLSCertFile == "") != (c.Dashboard.TLSKeyFile == "") {
			p.addf("dashboard.tls_cert_file and dashboard.tls_key_file must be set together")
		}
		if c.Dashboard.RateLimitPerMinute < 1 {
			p.addf("dashboard.rate_limit_per_minute must be at least 1")
		}
		if len(c.Dashboard.AllowedHosts) == 0 {
			p.addf("dashboard.allowed_hosts must not be empty: the Host allow-list is what prevents DNS rebinding attacks against the local API")
		}
	}

	// ---- privacy ---------------------------------------------------------------
	if c.Privacy.PayloadInspection {
		p.addf("privacy.payload_inspection must be false: iPulse performs no payload capture or TLS interception")
	}

	warnings = w
	if len(p.list) > 0 {
		return warnings, &ValidationError{Problems: p.list}
	}
	return warnings, nil
}

// Normalize applies canonical forms that validation and the runtime can rely on:
// lower-casing enumerations, adding implicit DNS ports, and ensuring the dashboard
// bind address is present in the Host allow-list.
func (c *Config) Normalize() {
	c.Logging.Level = strings.ToLower(strings.TrimSpace(c.Logging.Level))
	c.Logging.SyslogSeverity = strings.ToLower(strings.TrimSpace(c.Logging.SyslogSeverity))
	c.Latency.Method = strings.ToLower(strings.TrimSpace(c.Latency.Method))
	c.Connectivity.GatewayProbeMethod = strings.ToLower(strings.TrimSpace(c.Connectivity.GatewayProbeMethod))
	c.SpeedTest.EndpointSelection = strings.ToLower(strings.TrimSpace(c.SpeedTest.EndpointSelection))
	c.SpeedTest.Provider = strings.ToLower(strings.TrimSpace(c.SpeedTest.Provider))
	for i := range c.Connectivity.Targets {
		c.Connectivity.Targets[i].Type = strings.ToLower(strings.TrimSpace(c.Connectivity.Targets[i].Type))
	}
	c.DNS.Servers = normalizeDNSServers(c.DNS.Servers)
	c.DNS.FallbackServers = normalizeDNSServers(c.DNS.FallbackServers)
	for i := range c.DNS.Names {
		c.DNS.Names[i] = strings.TrimSuffix(strings.TrimSpace(c.DNS.Names[i]), ".")
	}
	if c.Dashboard.Enabled && c.Dashboard.Address != "" {
		host := c.Dashboard.Address
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		found := false
		for _, h := range c.Dashboard.AllowedHosts {
			if strings.EqualFold(h, host) || strings.EqualFold(h, c.Dashboard.Address) {
				found = true
				break
			}
		}
		if !found {
			c.Dashboard.AllowedHosts = append(c.Dashboard.AllowedHosts, host)
		}
	}
}

func normalizeDNSServers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Bare IP addresses get the standard DNS port.
		if _, err := netip.ParseAddr(s); err == nil {
			s = net.JoinHostPort(s, "53")
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateHostPort(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("must be host:port")
	}
	if host == "" {
		return errors.New("host part must not be empty")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	return validateDomain(host)
}

func validateHost(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return validateDomain(s)
}

func validateHostOrCIDR(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	return validateHost(s)
}

// validateDomain rejects anything that is not a plausible DNS name. This also guards
// against a value that would later be passed to a resolver or a URL.
func validateDomain(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if len(s) > 253 {
		return errors.New("name is longer than 253 characters")
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" {
			return errors.New("contains an empty label")
		}
		if len(label) > 63 {
			return errors.New("contains a label longer than 63 characters")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			case ch == '-' && i > 0 && i < len(label)-1:
			case ch == '_':
			default:
				return fmt.Errorf("contains invalid character %q", string(ch))
			}
		}
	}
	return nil
}

func validateURL(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("is not a valid URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	case "file":
		return nil
	default:
		return fmt.Errorf("scheme %q is not supported (use http, https or file)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("is missing a host")
	}
	return nil
}
