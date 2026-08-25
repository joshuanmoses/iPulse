//go:build linux

package linux

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ipulse/ipulse/internal/platform/types"
)

const (
	procRoot     = "/proc"
	sysClassNet  = "/sys/class/net"
	procNetTCP   = "/proc/net/tcp"
	procNetTCP6  = "/proc/net/tcp6"
	procNetUDP   = "/proc/net/udp"
	procNetUDP6  = "/proc/net/udp6"
	procNetRoute = "/proc/net/route"
	procNetIPv6  = "/proc/net/ipv6_route"
	procNetWless = "/proc/net/wireless"
	resolvConf   = "/etc/resolv.conf"
)

// Interfaces reads interface state from sysfs and addresses from the kernel's netlink
// interface (via net.Interfaces, which uses RTM_GETADDR internally).
func (p *Provider) Interfaces() ([]types.Interface, error) {
	sysIfaces, sysErr := os.ReadDir(sysClassNet)
	goIfaces, goErr := net.Interfaces()
	if sysErr != nil && goErr != nil {
		return nil, fmt.Errorf("linux: cannot enumerate interfaces: %w", goErr)
	}

	// Address and flag information comes from the netlink-backed standard library;
	// counters and link details come from sysfs.
	addrsByName := map[string][]netip.Prefix{}
	metaByName := map[string]net.Interface{}
	for _, gi := range goIfaces {
		metaByName[gi.Name] = gi
		addrs, err := gi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
					ones, _ := ipn.Mask.Size()
					addrsByName[gi.Name] = append(addrsByName[gi.Name], netip.PrefixFrom(addr.Unmap(), ones))
				}
			}
		}
	}

	names := make([]string, 0, len(sysIfaces))
	if sysErr == nil {
		for _, e := range sysIfaces {
			names = append(names, e.Name())
		}
	} else {
		for name := range metaByName {
			names = append(names, name)
		}
	}

	out := make([]types.Interface, 0, len(names))
	for _, name := range names {
		iface := types.Interface{Name: name, Addrs: addrsByName[name]}
		if gi, ok := metaByName[name]; ok {
			iface.Index = gi.Index
			iface.MTU = gi.MTU
			iface.MAC = gi.HardwareAddr.String()
			iface.Up = gi.Flags&net.FlagUp != 0
			iface.Type = types.ClassifyInterface(name,
				gi.Flags&net.FlagLoopback != 0,
				gi.Flags&net.FlagPointToPoint != 0,
				isWireless(name))
		} else {
			iface.Type = types.ClassifyInterface(name, name == "lo", false, isWireless(name))
			iface.Up = readSysString(name, "operstate") == "up"
			iface.MAC = readSysString(name, "address")
			iface.MTU = int(readSysInt(name, "mtu"))
		}

		// operstate and carrier are the authoritative link state: an interface can be
		// administratively up with no cable plugged in, which is exactly the case that
		// distinguishes a local interface failure from an upstream one.
		switch readSysString(name, "operstate") {
		case "up":
			iface.Up, iface.Running = true, true
		case "down":
			iface.Up, iface.Running = false, false
		case "unknown":
			// Tunnels report unknown; fall back to the carrier file and the flags.
			iface.Running = readSysInt(name, "carrier") == 1 || iface.Up
		default:
			iface.Running = readSysInt(name, "carrier") == 1
		}
		if readSysInt(name, "carrier") == 0 && iface.Type == types.IfaceEthernet {
			iface.Running = false
		}
		if speed := readSysInt(name, "speed"); speed > 0 {
			iface.SpeedMbps = int(speed)
		}
		iface.Counters = readCounters(name)
		out = append(out, iface)
	}
	return out, nil
}

func isWireless(name string) bool {
	if _, err := os.Stat(filepath.Join(sysClassNet, name, "wireless")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(sysClassNet, name, "phy80211")); err == nil {
		return true
	}
	return false
}

func wirelessInterfaces() ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if isWireless(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func readSysString(iface, file string) string {
	b, err := os.ReadFile(filepath.Join(sysClassNet, iface, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readSysInt(iface, file string) int64 {
	s := readSysString(iface, file)
	if s == "" {
		return -1
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return v
}

func readStatistic(iface, name string) uint64 {
	b, err := os.ReadFile(filepath.Join(sysClassNet, iface, "statistics", name))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readCounters(iface string) types.Counters {
	return types.Counters{
		RxBytes:   readStatistic(iface, "rx_bytes"),
		TxBytes:   readStatistic(iface, "tx_bytes"),
		RxPackets: readStatistic(iface, "rx_packets"),
		TxPackets: readStatistic(iface, "tx_packets"),
		RxErrors:  readStatistic(iface, "rx_errors"),
		TxErrors:  readStatistic(iface, "tx_errors"),
		RxDropped: readStatistic(iface, "rx_dropped"),
		TxDropped: readStatistic(iface, "tx_dropped"),
	}
}
