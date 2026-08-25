//go:build windows

package windows

import (
	"net/netip"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Routes reports the routes iPulse needs: the default route per adapter and per family,
// plus the on-link prefixes of each adapter.
//
// The gateway list and interface metrics come from GetAdaptersAddresses, which is the
// documented way to obtain the active default gateways and is stable across Windows
// versions. iPulse uses routes for three things - finding the default gateway to probe,
// noticing when the default route moves (VPN connect, Wi-Fi/Ethernet handover), and
// deciding whether an address is on-link - and adapter gateway information answers all
// three without hand-declaring the large MIB_IPFORWARD_ROW2 structure.
func (p *Provider) Routes() ([]types.Route, error) {
	adapters, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var out []types.Route
	for _, a := range adapters {
		name := utf16PtrToString(a.FriendlyName)
		if name == "" {
			continue
		}
		for gw := a.FirstGatewayAddress; gw != nil; gw = gw.Next {
			addr, ok := sockaddrToAddr(gw.Address)
			if !ok || !addr.IsValid() {
				continue
			}
			metric := int(a.Ipv4Metric)
			zero := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			if addr.Is6() {
				metric = int(a.Ipv6Metric)
				zero = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			}
			out = append(out, types.Route{
				Destination: zero,
				Gateway:     addr,
				Interface:   name,
				Metric:      metric,
				Default:     true,
			})
		}
		for ua := a.FirstUnicastAddress; ua != nil; ua = ua.Next {
			addr, ok := sockaddrToAddr(ua.Address)
			if !ok {
				continue
			}
			bits := int(ua.OnLinkPrefixLength)
			if bits <= 0 || bits > addr.BitLen() {
				continue
			}
			prefix := netip.PrefixFrom(addr, bits).Masked()
			metric := int(a.Ipv4Metric)
			if addr.Is6() {
				metric = int(a.Ipv6Metric)
			}
			out = append(out, types.Route{
				Destination: prefix,
				Interface:   name,
				Metric:      metric,
			})
		}
	}
	return out, nil
}
