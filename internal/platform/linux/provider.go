//go:build linux

// Package linux implements the iPulse platform abstraction on Linux using the kernel's
// own exported interfaces: /proc, /sys and a small number of ioctls. It never shells
// out to ip, ss, iw or netstat, so it works in minimal containers, cannot be affected
// by PATH, and cannot be tricked by command output parsing.
package linux

import (
	"os"
	"runtime"
	"syscall"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Provider is the Linux platform provider.
type Provider struct{}

// New returns a Linux provider.
func New() *Provider { return &Provider{} }

// Name identifies the implementation.
func (p *Provider) Name() string { return "linux" }

// Capabilities probes what this process may actually do, and records why anything is
// unavailable. The notes are surfaced verbatim by `ipulse diagnostics --privileges`.
func (p *Provider) Capabilities() types.Capabilities {
	c := types.Capabilities{
		Platform:   "linux/" + runtime.GOARCH,
		Elevated:   os.Geteuid() == 0,
		Interfaces: true,
		Routes:     true,
		DNSServers: true,
	}

	// Socket tables are world-readable; process attribution needs to read other
	// users' /proc/<pid>/fd, which requires root or CAP_DAC_READ_SEARCH.
	if _, err := os.Stat(procNetTCP); err == nil {
		c.Connections = true
	} else {
		c.Note("connections", "cannot read "+procNetTCP+": "+err.Error())
	}
	c.ProcessAttribution = canReadOtherProcesses()
	if !c.ProcessAttribution {
		c.Note("process_attribution",
			"sockets owned by other users cannot be attributed; grant CAP_DAC_READ_SEARCH or run as root")
	}

	if icmpAvailable() {
		c.ICMP = true
		c.Traceroute = true
	} else {
		c.Note("icmp",
			"ICMP sockets are not permitted; latency and packet loss fall back to TCP connect timing. "+
				"Grant CAP_NET_RAW, or widen net.ipv4.ping_group_range, to enable ICMP")
		c.Note("traceroute", "path measurement needs ICMP; grant CAP_NET_RAW to enable it")
	}

	if ifaces, err := wirelessInterfaces(); err == nil && len(ifaces) > 0 {
		c.Wireless = true
	} else {
		c.Note("wireless", "no wireless interface detected")
	}
	return c
}

// canReadOtherProcesses tests whether socket-to-process attribution will work for
// processes owned by other users. Reading our own /proc entry always works, so the
// probe looks for a process we do not own.
func canReadOtherProcesses() bool {
	if os.Geteuid() == 0 {
		return true
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	self := os.Getpid()
	tried := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, ok := atoiSafe(e.Name())
		if !ok || pid == self || pid <= 1 {
			continue
		}
		st, err := os.Stat(procRoot + "/" + e.Name())
		if err != nil {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == os.Geteuid() {
			continue // our own process, not a useful probe
		}
		tried++
		if _, err := os.ReadDir(procRoot + "/" + e.Name() + "/fd"); err == nil {
			return true
		}
		if tried >= 5 {
			break
		}
	}
	// No other user's process to test against: assume attribution works rather than
	// reporting a limitation that may not exist.
	return tried == 0
}

// icmpAvailable reports whether this process can open an ICMP socket, either as an
// unprivileged datagram ping socket or as a raw socket.
func icmpAvailable() bool {
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, protoICMP); err == nil {
		_ = syscall.Close(fd)
		return true
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protoICMP); err == nil {
		_ = syscall.Close(fd)
		return true
	}
	return false
}

const protoICMP = 1

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
