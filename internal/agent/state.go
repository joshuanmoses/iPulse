package agent

import (
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/platform"
)

// LinkStatus is the coarse Internet state shown at the top of the dashboard.
type LinkStatus string

// Link statuses.
const (
	StatusOnline   LinkStatus = "ONLINE"
	StatusDegraded LinkStatus = "DEGRADED"
	StatusOffline  LinkStatus = "OFFLINE"
	StatusStarting LinkStatus = "STARTING"
)

// WiFiState is the current wireless association.
type WiFiState struct {
	Interface    string  `json:"interface"`
	SSID         string  `json:"ssid,omitempty"`
	BSSID        string  `json:"bssid,omitempty"`
	SignalDBM    int     `json:"signal_dbm"`
	SignalPct    int     `json:"signal_percent"`
	LinkMbps     float64 `json:"link_mbps"`
	FrequencyMHz int     `json:"frequency_mhz,omitempty"`
	Channel      int     `json:"channel,omitempty"`
	Band         string  `json:"band,omitempty"`
}

// Snapshot is an immutable view of the agent's current understanding of the connection.
// The CLI, the API and the dashboard all render this one structure.
type Snapshot struct {
	Time      time.Time     `json:"time"`
	StartedAt time.Time     `json:"started_at"`
	Uptime    time.Duration `json:"uptime"`
	Status    LinkStatus    `json:"status"`
	Online    bool          `json:"online"`

	HealthScore      float64            `json:"health_score"`
	HealthComponents map[string]float64 `json:"health_components,omitempty"`

	// Live quality measurements.
	LatencyMS     float64 `json:"latency_ms"`
	JitterMS      float64 `json:"jitter_ms"`
	PacketLossPct float64 `json:"packet_loss_pct"`
	GatewayRTTMS  float64 `json:"gateway_rtt_ms,omitempty"`
	DNSMS         float64 `json:"dns_ms,omitempty"`

	// Throughput. DownloadMbps/UploadMbps come from the last full speed test;
	// EstimatedDownloadMbps comes from the cheaper lightweight probe in between.
	DownloadMbps          float64   `json:"download_mbps"`
	UploadMbps            float64   `json:"upload_mbps"`
	EstimatedDownloadMbps float64   `json:"estimated_download_mbps,omitempty"`
	LastSpeedTest         time.Time `json:"last_speed_test,omitempty"`
	LastSpeedTestServer   string    `json:"last_speed_test_server,omitempty"`
	ExpectedDownloadMbps  float64   `json:"expected_download_mbps,omitempty"`
	ExpectedUploadMbps    float64   `json:"expected_upload_mbps,omitempty"`

	// Current traffic rates from interface counters.
	RxBps float64 `json:"rx_bps"`
	TxBps float64 `json:"tx_bps"`

	// Network identity.
	PublicIPv4    string   `json:"public_ipv4,omitempty"`
	PublicIPv6    string   `json:"public_ipv6,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	ISP           string   `json:"isp,omitempty"`
	Country       string   `json:"country,omitempty"`
	CGNAT         bool     `json:"cgnat,omitempty"`
	Interface     string   `json:"interface,omitempty"`
	InterfaceType string   `json:"interface_type,omitempty"`
	LocalIP       string   `json:"local_ip,omitempty"`
	Gateway       string   `json:"gateway,omitempty"`
	VPNActive     bool     `json:"vpn_active"`
	DNSServers    []string `json:"dns_servers,omitempty"`

	WiFi *WiFiState `json:"wifi,omitempty"`

	// Availability and outages.
	CurrentOutage   *database.Outage `json:"current_outage,omitempty"`
	AvailabilityPct float64          `json:"availability_percent"`
	Outages24h      int              `json:"outages_24h"`

	// Counters.
	ActiveConnections int   `json:"active_connections"`
	KnownDestinations int64 `json:"known_destinations"`
	Indicators        int64 `json:"threat_indicators"`
	ThreatMatches24h  int64 `json:"threat_matches_24h"`
	EventsLogged      int64 `json:"events_logged"`

	// Diagnostics context.
	Capabilities  platform.Capabilities `json:"capabilities"`
	LastDiagnosis string                `json:"last_diagnosis,omitempty"`
	Version       string                `json:"version"`
	Platform      string                `json:"platform"`
	Degraded      []string              `json:"degraded,omitempty"`
}

// State holds the agent's mutable runtime view. Collectors write to it; the API and CLI
// read snapshots. One mutex is enough: writes are small and infrequent relative to the
// work that produces them.
type State struct {
	mu   sync.RWMutex
	snap Snapshot
}

// NewState creates the initial state.
func NewState(version, plat string, caps platform.Capabilities) *State {
	now := time.Now()
	return &State{snap: Snapshot{
		Time:         now,
		StartedAt:    now,
		Status:       StatusStarting,
		Version:      version,
		Platform:     plat,
		Capabilities: caps,
		Degraded:     caps.Limitations(),
	}}
}

// Snapshot returns a copy of the current state.
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.snap
	out.Time = time.Now()
	out.Uptime = out.Time.Sub(out.StartedAt).Round(time.Second)
	// Copy the mutable reference fields so a caller cannot mutate agent state.
	if s.snap.WiFi != nil {
		w := *s.snap.WiFi
		out.WiFi = &w
	}
	if s.snap.CurrentOutage != nil {
		o := *s.snap.CurrentOutage
		out.CurrentOutage = &o
	}
	if len(s.snap.HealthComponents) > 0 {
		out.HealthComponents = make(map[string]float64, len(s.snap.HealthComponents))
		for k, v := range s.snap.HealthComponents {
			out.HealthComponents[k] = v
		}
	}
	if len(s.snap.DNSServers) > 0 {
		out.DNSServers = append([]string(nil), s.snap.DNSServers...)
	}
	if len(s.snap.Degraded) > 0 {
		out.Degraded = append([]string(nil), s.snap.Degraded...)
	}
	return out
}

// Update applies a mutation under the lock.
func (s *State) Update(fn func(*Snapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.snap)
}

// SetStatus updates the coarse link status.
func (s *State) SetStatus(status LinkStatus) {
	s.Update(func(snap *Snapshot) {
		snap.Status = status
		snap.Online = status == StatusOnline || status == StatusDegraded
	})
}

// Online reports whether the link is currently considered usable.
func (s *State) Online() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.Online
}

// Status returns the current link status.
func (s *State) Status() LinkStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.Status
}

// CurrentInterface returns the interface carrying the default route.
func (s *State) CurrentInterface() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.Interface
}

// Gateway returns the current default gateway.
func (s *State) Gateway() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.Gateway
}

// PublicIP returns the current public addresses.
func (s *State) PublicIP() (v4, v6 string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.PublicIPv4, s.snap.PublicIPv6
}

// VPNActive reports whether a tunnel currently carries the default route.
func (s *State) VPNActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.VPNActive
}
