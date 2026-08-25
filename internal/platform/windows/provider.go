//go:build windows

// Package windows implements the iPulse platform abstraction on Windows using native
// Win32 APIs: iphlpapi for interfaces, addresses, routes and the extended socket
// tables, wlanapi for wireless telemetry, and the process/token APIs for socket
// attribution. No output of netsh, ipconfig, netstat or PowerShell is ever parsed.
package windows

import (
	"runtime"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Provider is the Windows platform provider.
type Provider struct{}

// New returns a Windows provider.
func New() *Provider { return &Provider{} }

// Name identifies the implementation.
func (p *Provider) Name() string { return "windows" }

// Capabilities probes what this process may actually do.
//
// Windows specifics worth knowing:
//   - The extended TCP/UDP tables return the owning PID for every socket on the system
//     without elevation, but opening those processes to read their image path does need
//     rights that a non-elevated process lacks for other users' processes.
//   - ICMP echo through the Windows raw-socket path requires Administrator; iPulse
//     falls back to TCP connect timing when it is unavailable.
//   - The WLAN service (wlansvc) must be running for wireless telemetry.
func (p *Provider) Capabilities() types.Capabilities {
	c := types.Capabilities{
		Platform:    "windows/" + runtime.GOARCH,
		Elevated:    isElevated(),
		Interfaces:  true,
		Routes:      true,
		Connections: true,
		DNSServers:  true,
	}

	c.ProcessAttribution = true
	if !c.Elevated {
		c.Note("process_attribution",
			"executable paths and account names for other users' processes need Administrator; "+
				"process names from the socket tables are still available")
	}

	if icmpAvailable() {
		c.ICMP = true
		c.Traceroute = true
	} else {
		c.Note("icmp",
			"ICMP echo requires Administrator on Windows; latency and packet loss fall back to TCP connect timing")
		c.Note("traceroute", "path measurement needs ICMP; run the service as Administrator to enable it")
	}

	if links, err := p.Wireless(); err == nil && len(links) > 0 {
		c.Wireless = true
	} else if err != nil {
		c.Note("wireless", "wireless telemetry unavailable: "+err.Error())
	}
	return c
}

func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

// icmpAvailable probes whether a raw ICMP socket can be created. iPulse uses the
// standard socket path rather than IcmpSendEcho so the same measurement code runs on
// both platforms.
func icmpAvailable() bool {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	_ = windows.Closesocket(fd)
	return true
}
