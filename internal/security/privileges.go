package security

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
)

// FeatureRequirement documents one monitoring function's privilege requirement, whether
// it is currently available, and what iPulse does instead when it is not.
//
// This table is the machine-readable version of the privilege matrix in
// docs/security.md, and it is what `ipulse diagnostics --privileges` prints. Keeping it
// in code means the documentation cannot drift from behaviour.
type FeatureRequirement struct {
	Feature   string `json:"feature"`
	Required  string `json:"required"`
	Available bool   `json:"available"`
	Fallback  string `json:"fallback,omitempty"`
	Impact    string `json:"impact,omitempty"`
}

// PrivilegeReport summarises the process's effective privileges.
type PrivilegeReport struct {
	Platform string               `json:"platform"`
	User     string               `json:"user"`
	UID      int                  `json:"uid,omitempty"`
	Elevated bool                 `json:"elevated"`
	Features []FeatureRequirement `json:"features"`
}

// Degraded returns the features that are currently unavailable.
func (r PrivilegeReport) Degraded() []FeatureRequirement {
	var out []FeatureRequirement
	for _, f := range r.Features {
		if !f.Available {
			out = append(out, f)
		}
	}
	return out
}

// Capabilities is the subset of platform.Capabilities the report needs. It is declared
// here rather than imported so internal/security stays a leaf package.
type Capabilities struct {
	Platform           string
	Elevated           bool
	Interfaces         bool
	Routes             bool
	Connections        bool
	ProcessAttribution bool
	Wireless           bool
	ICMP               bool
	Traceroute         bool
	DNSServers         bool
}

// BuildPrivilegeReport turns platform capabilities into the documented matrix.
func BuildPrivilegeReport(caps Capabilities) PrivilegeReport {
	r := PrivilegeReport{
		Platform: caps.Platform,
		Elevated: caps.Elevated,
		User:     currentUser(),
	}
	if runtime.GOOS != "windows" {
		r.UID = os.Geteuid()
	}

	icmpReq := "CAP_NET_RAW, or net.ipv4.ping_group_range covering the service group"
	attrReq := "CAP_DAC_READ_SEARCH or root"
	if runtime.GOOS == "windows" {
		icmpReq = "Administrator"
		attrReq = "Administrator (for other users' processes)"
	}

	r.Features = []FeatureRequirement{
		{
			Feature: "Connectivity, DNS and HTTPS probes", Required: "none",
			Available: true,
		},
		{
			Feature: "Speed testing", Required: "none",
			Available: true,
		},
		{
			Feature: "Interface counters and link state", Required: "none",
			Available: caps.Interfaces,
			Impact:    "traffic monitoring and bandwidth anomaly detection are unavailable",
		},
		{
			Feature: "Routing table and default gateway", Required: "none",
			Available: caps.Routes,
			Impact:    "gateway diagnostics and route-change detection are unavailable",
		},
		{
			Feature: "Active connection table", Required: "none",
			Available: caps.Connections,
			Impact:    "connection, destination and lateral-movement analysis are unavailable",
		},
		{
			Feature: "Process attribution for connections", Required: attrReq,
			Available: caps.ProcessAttribution,
			Fallback:  "connections are recorded without a process name or executable path",
			Impact:    "events cannot name the responsible application",
		},
		{
			Feature: "ICMP latency and packet loss", Required: icmpReq,
			Available: caps.ICMP,
			Fallback:  "TCP connect timing to the configured latency targets",
			Impact:    "packet loss is inferred from failed TCP handshakes, which is coarser",
		},
		{
			Feature: "Path/route measurement (traceroute)", Required: icmpReq,
			Available: caps.Traceroute,
			Fallback:  "none; path monitoring is disabled",
			Impact:    "route-change detection and per-hop latency are unavailable",
		},
		{
			Feature: "Wireless telemetry (SSID, RSSI, link rate)", Required: "none on Linux; the WLAN service on Windows",
			Available: caps.Wireless,
			Fallback:  "none; Wi-Fi degradation cannot be distinguished from ISP problems",
		},
		{
			Feature: "System resolver discovery", Required: "none",
			Available: caps.DNSServers,
			Fallback:  "the configured dns.fallback_servers are used instead",
		},
		{
			Feature: "Windows Event Log source registration", Required: "Administrator (installer only)",
			Available: runtime.GOOS != "windows" || caps.Elevated,
			Fallback:  "events still reach the log files and the database",
		},
	}
	return r
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		if u.Username != "" {
			return u.Username
		}
		return u.Uid
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("USERNAME")
	}
	return strconv.Itoa(os.Geteuid())
}

// IsElevated reports whether the process has administrative privileges. The
// platform-specific detail lives in the platform provider; this is the cheap check used
// by the CLI before attempting an installation.
func IsElevated() bool { return isElevated() }
