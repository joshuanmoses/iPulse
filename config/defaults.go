package config

import "time"

func dur(d time.Duration) Duration { return Duration(d) }

func boolPtr(b bool) *bool { return &b }

// Default returns the complete default configuration. Every field is set here, so a
// missing key in ipulse.yaml always resolves to a documented value rather than a Go
// zero value.
//
// Probe targets deliberately span several independent networks (Cloudflare AS13335,
// Google AS15169, Quad9 AS19281, OpenDNS AS36692). Diversity is what allows iPulse to
// tell "one provider is down" apart from "our Internet is down".
func Default() Config {
	return Config{
		Service: ServiceConfig{
			DataDir:         "",
			LogDir:          "",
			ShutdownTimeout: dur(20 * time.Second),
			StartupGrace:    dur(45 * time.Second),
		},
		Monitoring: MonitoringConfig{
			HealthInterval:        dur(15 * time.Second),
			DNSInterval:           dur(30 * time.Second),
			LatencyInterval:       dur(30 * time.Second),
			InterfaceInterval:     dur(30 * time.Second),
			WiFiInterval:          dur(60 * time.Second),
			PublicIPInterval:      dur(5 * time.Minute),
			RouteInterval:         dur(30 * time.Minute),
			TrafficInterval:       dur(5 * time.Second),
			ConnectionInterval:    dur(15 * time.Second),
			HealthScoreInterval:   dur(1 * time.Minute),
			BaselineFlushInterval: dur(5 * time.Minute),
			RetentionInterval:     dur(6 * time.Hour),
			AvailabilityInterval:  dur(24 * time.Hour),
			ThreatFeedInterval:    dur(12 * time.Hour),
			ProbeTimeout:          dur(5 * time.Second),
			Jitter:                dur(2 * time.Second),
		},
		Connectivity: ConnectivityConfig{
			Targets: []Target{
				{Name: "cloudflare-dns", Type: "tcp", Address: "1.1.1.1:443", Notes: "AS13335"},
				{Name: "google-dns", Type: "tcp", Address: "8.8.8.8:443", Notes: "AS15169"},
				{Name: "quad9-dns", Type: "tcp", Address: "9.9.9.9:443", Notes: "AS19281"},
			},
			RequiredSuccess: 1,
			IPLiterals:      []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"},
			HTTPSTargets: []string{
				"https://www.cloudflare.com/cdn-cgi/trace",
				"https://connectivitycheck.gstatic.com/generate_204",
				"https://checkip.amazonaws.com",
			},
			FailuresBeforeOutage:    2,
			SuccessesBeforeRecovery: 2,
			GatewayProbeMethod:      "auto",
			GatewayTCPPorts:         []int{80, 443, 53},
		},
		DNS: DNSConfig{
			Names:             []string{"www.google.com", "cloudflare.com", "wikipedia.org", "github.com"},
			Servers:           nil,
			FallbackServers:   []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
			Timeout:           dur(3 * time.Second),
			SlowThreshold:     dur(250 * time.Millisecond),
			UseSystemResolver: true,
		},
		Latency: LatencyConfig{
			Targets:        []string{"1.1.1.1", "8.8.8.8"},
			Probes:         5,
			Spacing:        dur(200 * time.Millisecond),
			Timeout:        dur(2 * time.Second),
			Method:         "auto",
			TCPPort:        443,
			IncludeGateway: true,
		},
		SpeedTest: SpeedTestConfig{
			Enabled:              true,
			Provider:             "http",
			LightweightInterval:  dur(5 * time.Minute),
			FullInterval:         dur(30 * time.Minute),
			ExpectedDownloadMbps: 0,
			ExpectedUploadMbps:   0,
			Streams:              4,
			Warmup:               dur(2 * time.Second),
			Duration:             dur(10 * time.Second),
			UploadDuration:       dur(8 * time.Second),
			MaxDownloadBytes:     512 * 1024 * 1024,
			MaxUploadBytes:       128 * 1024 * 1024,
			LightweightBytes:     2 * 1024 * 1024,
			SkipIfBusyMbps:       10,
			EndpointSelection:    "latency",
			UploadEnabled:        true,
			Timeout:              dur(90 * time.Second),
			Endpoints: []SpeedEndpoint{
				{
					Name:        "cloudflare",
					DownloadURL: "https://speed.cloudflare.com/__down?bytes={bytes}",
					UploadURL:   "https://speed.cloudflare.com/__up",
					LatencyURL:  "https://speed.cloudflare.com/__down?bytes=1000",
					MaxStreams:  8,
					Location:    "anycast",
					Enabled:     boolPtr(true),
				},
				{
					Name:        "hetzner",
					DownloadURL: "https://speed.hetzner.de/100MB.bin",
					MaxStreams:  4,
					Location:    "Germany",
					Enabled:     boolPtr(false),
				},
			},
		},
		Traffic: TrafficConfig{
			Enabled:             true,
			ExcludeInterfaces:   []string{"lo", "lo*", "docker*", "br-*", "veth*", "virbr*", "Loopback*"},
			SpikeZScore:         6,
			SpikeMinMbps:        5,
			SustainedSeconds:    300,
			SustainedUploadMbps: 2,
			LargeTransferMB:     512,
			QuietHoursStart:     1,
			QuietHoursEnd:       6,
			ExcludeSelfTraffic:  true,
			ErrorRateThreshold:  5,
		},
		Connections: ConnectionsConfig{
			Enabled:                 true,
			IncludeUDP:              true,
			IncludeListening:        false,
			IncludeLoopback:         false,
			ResolveProcess:          true,
			MaxConnectionsPerSample: 4096,
			IdleTimeout:             dur(5 * time.Minute),
		},
		Destinations: DestinationsConfig{
			Enabled:              true,
			NewDestinationWindow: dur(24 * time.Hour),
			LearningPeriod:       dur(2 * time.Hour),
			RarePercentile:       5,
			HighVolumeMB:         64,
			FanoutWindow:         dur(1 * time.Minute),
			FanoutThreshold:      60,
			ExpectedPorts:        []int{53, 80, 123, 443, 465, 587, 853, 993, 995, 5223, 8443},
			ReverseDNS:           true,
			Enrichment:           nil,
			IgnoreDestinations:   nil,
			IgnoreProcesses:      nil,
		},
		ThreatIntel: ThreatIntelConfig{
			Enabled:       true,
			Feeds:         nil,
			MaxIndicators: 2_000_000,
			ExpireAfter:   dur(30 * 24 * time.Hour),
			MatchPrivate:  false,
			AllowList:     nil,
		},
		Lateral: LateralConfig{
			Enabled:                   true,
			Window:                    dur(2 * time.Minute),
			HostSweepThreshold:        20,
			PortScanThreshold:         15,
			FailedConnectionThreshold: 25,
			AdminPorts:                []int{22, 135, 139, 445, 3389, 5900, 5985, 5986},
			AdminSweepHosts:           5,
			AllowProcesses:            nil,
			ExtraPrivateRanges:        nil,
		},
		PublicIP: PublicIPConfig{
			Enabled: true,
			Providers: []string{
				"https://1.1.1.1/cdn-cgi/trace",
				"https://api.ipify.org",
				"https://icanhazip.com",
			},
			IPv6Providers: []string{
				"https://api6.ipify.org",
				"https://ipv6.icanhazip.com",
			},
			Timeout:        dur(6 * time.Second),
			ConfirmChanges: true,
			ASNLookup:      true,
			ASNProviderURL: "",
		},
		Routing: RoutingConfig{
			Enabled:            true,
			Destinations:       []string{"1.1.1.1", "8.8.8.8"},
			MaxHops:            20,
			ProbesPerHop:       1,
			Timeout:            dur(20 * time.Second),
			HopChangeTolerance: 1,
		},
		WiFi: WiFiConfig{
			Enabled:                 true,
			WeakSignalDBM:           -70,
			LinkSpeedDegradePercent: 50,
		},
		Baseline: BaselineConfig{
			MinObservations: 30,
			Window:          dur(14 * 24 * time.Hour),
			TimeBuckets:     true,
			BucketHours:     1,
			EWMAAlpha:       0.1,
			ReservoirSize:   256,
			MaxSampleAge:    dur(30 * 24 * time.Hour),
		},
		Alerts: AlertsConfig{
			DownloadDegradationPercent: 40,
			UploadDegradationPercent:   40,
			LatencyDegradationPercent:  100,
			JitterDegradationPercent:   150,
			PacketLossPercent:          2,
			DNSDegradationPercent:      200,
			ISPShortfallPercent:        30,
			SustainedUploadSeconds:     120,
			SustainedLatencySeconds:    120,
			SustainedBandwidthSeconds:  300,
			Persistence:                2,
			RecoveryPersistence:        3,
			Cooldown:                   dur(15 * time.Minute),
			MinAbsoluteLatencyMS:       30,
			MinAbsoluteMbps:            5,
		},
		Correlation: CorrelationConfig{
			Enabled:              true,
			Window:               dur(3 * time.Minute),
			SuppressContributing: true,
		},
		Health: HealthConfig{
			Enabled: true,
			Weights: HealthWeights{
				Availability: 30,
				Download:     15,
				Upload:       10,
				Latency:      20,
				Jitter:       8,
				PacketLoss:   12,
				DNS:          5,
			},
			Window:        dur(1 * time.Hour),
			WarnBelow:     70,
			LatencyGoodMS: 20,
			LatencyBadMS:  200,
			JitterGoodMS:  3,
			JitterBadMS:   50,
			LossGoodPct:   0,
			LossBadPct:    5,
			DNSGoodMS:     20,
			DNSBadMS:      500,
		},
		Logging: LoggingConfig{
			Level:          "info",
			Text:           true,
			JSON:           true,
			Database:       true,
			Syslog:         true,
			EventLog:       true,
			Console:        false,
			SyslogSeverity: "notice",
			MaxFileMB:      100,
			MaxArchives:    10,
			RetentionDays:  30,
			Compress:       true,
			RotateDaily:    false,
			FileMode:       "0640",
		},
		Database: DatabaseConfig{
			Path:        "",
			BusyTimeout: dur(5 * time.Second),
			Retention: RetentionConfig{
				EventsDays:       90,
				MeasurementsDays: 30,
				SpeedTestsDays:   365,
				OutagesDays:      365,
				ConnectionsDays:  14,
				DestinationsDays: 180,
				TrafficDays:      30,
				AggregatesDays:   730,
			},
			MaxSizeMB:      2048,
			VacuumInterval: dur(24 * time.Hour),
			Downsample:     true,
		},
		Dashboard: DashboardConfig{
			Enabled:            true,
			Address:            "127.0.0.1",
			Port:               8750,
			AuthToken:          "",
			AllowedHosts:       []string{"127.0.0.1", "localhost", "[::1]"},
			AllowRemoteTests:   false,
			ReadTimeout:        dur(15 * time.Second),
			WriteTimeout:       dur(60 * time.Second),
			RateLimitPerMinute: 10,
		},
		Privacy: PrivacyConfig{
			CollectProcessNames:     true,
			CollectExecutablePaths:  true,
			CollectUsernames:        true,
			CollectRemoteHostnames:  true,
			AnonymizeLocalAddresses: false,
			PayloadInspection:       false,
		},
	}
}

// ResolvedPaths fills in empty path fields with the platform defaults. It is applied
// after loading so that the rest of the agent never has to think about defaults.
func (c *Config) ResolvedPaths() {
	if c.Service.DataDir == "" {
		c.Service.DataDir = DefaultDataDir()
	}
	if c.Service.LogDir == "" {
		c.Service.LogDir = DefaultLogDir()
	}
	if c.Database.Path == "" {
		c.Database.Path = joinPath(c.Service.DataDir, "ipulse.db")
	}
}
