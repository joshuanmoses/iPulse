//go:build windows

package windows

import (
	"net/netip"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// DNSServers reads the resolvers Windows is configured to use, from the per-adapter
// DNS server list returned by GetAdaptersAddresses. Only adapters that are up are
// consulted, because a disconnected adapter's stale resolvers would make DNS
// diagnostics report failures against servers the system is not actually using.
func (p *Provider) DNSServers() ([]netip.AddrPort, error) {
	adapters, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var out []netip.AddrPort
	seen := map[string]bool{}
	for _, a := range adapters {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for ds := a.FirstDnsServerAddress; ds != nil; ds = ds.Next {
			addr, ok := sockaddrToAddr(ds.Address)
			if !ok || !addr.IsValid() {
				continue
			}
			// Windows lists the site-local anycast addresses of the "well-known" DNS
			// discovery mechanism on adapters with no real resolver; they are not
			// usable and would produce spurious DNS failures.
			if addr.Is6() && (addr.String() == "fec0:0:0:ffff::1" ||
				addr.String() == "fec0:0:0:ffff::2" || addr.String() == "fec0:0:0:ffff::3") {
				continue
			}
			ap := netip.AddrPortFrom(addr, 53)
			if seen[ap.String()] {
				continue
			}
			seen[ap.String()] = true
			out = append(out, ap)
		}
	}
	if len(out) == 0 {
		return nil, types.ErrNotFound
	}
	return out, nil
}
