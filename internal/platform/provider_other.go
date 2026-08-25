//go:build !linux && !windows

package platform

import (
	"net"
	"net/netip"
	"runtime"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// unsupportedProvider keeps iPulse buildable and partially usable on platforms it does
// not target (macOS and BSD development machines, for example). Interfaces come from
// the standard library; everything platform-specific reports ErrUnsupported so callers
// exercise exactly the same degradation paths they would on a restricted Linux host.
type unsupportedProvider struct{}

func newProvider() Provider { return unsupportedProvider{} }

func (unsupportedProvider) Name() string { return runtime.GOOS + " (unsupported)" }

func (unsupportedProvider) Capabilities() Capabilities {
	c := Capabilities{Platform: runtime.GOOS + "/" + runtime.GOARCH, Interfaces: true}
	c.Note("platform", "iPulse supports Linux and Windows; this platform provides interface enumeration only")
	return c
}

// Interfaces returns what the standard library can see: names, flags, MTU and
// addresses, but no counters, so traffic monitoring is inert here.
func (unsupportedProvider) Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifaces))
	for _, gi := range ifaces {
		iface := Interface{
			Name:  gi.Name,
			Index: gi.Index,
			MTU:   gi.MTU,
			MAC:   gi.HardwareAddr.String(),
			Up:    gi.Flags&net.FlagUp != 0,
			Type: types.ClassifyInterface(gi.Name,
				gi.Flags&net.FlagLoopback != 0, gi.Flags&net.FlagPointToPoint != 0, false),
		}
		iface.Running = iface.Up
		if addrs, err := gi.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
						ones, _ := ipn.Mask.Size()
						iface.Addrs = append(iface.Addrs, netip.PrefixFrom(addr.Unmap(), ones))
					}
				}
			}
		}
		out = append(out, iface)
	}
	return out, nil
}

func (unsupportedProvider) Routes() ([]Route, error) { return nil, ErrUnsupported }

func (unsupportedProvider) Connections(ConnOptions) ([]Connection, error) {
	return nil, ErrUnsupported
}

func (unsupportedProvider) Wireless() ([]WirelessLink, error) { return nil, ErrUnsupported }

func (unsupportedProvider) DNSServers() ([]netip.AddrPort, error) { return nil, ErrUnsupported }

func (unsupportedProvider) ProcessInfo(int) (Process, error) { return Process{}, ErrUnsupported }
