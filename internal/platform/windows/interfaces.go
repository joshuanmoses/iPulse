//go:build windows

package windows

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Windows IF_TYPE values that matter for classification.
const (
	ifTypeOther          = 1
	ifTypeEthernetCSMACD = 6
	ifTypeSoftwareLoop   = 24
	ifTypePPP            = 23
	ifTypeTunnel         = 131
	ifTypeIEEE80211      = 71
)

// Interfaces enumerates adapters with GetAdaptersAddresses and fills in 64-bit counters
// from GetIfEntry2Ex. 32-bit counters (the older GetIfTable) would wrap in about 34
// seconds on a gigabit link, which is unusable for rate calculation.
func (p *Provider) Interfaces() ([]types.Interface, error) {
	adapters, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	out := make([]types.Interface, 0, len(adapters))
	for _, a := range adapters {
		iface := types.Interface{
			Index:       int(a.IfIndex),
			Name:        utf16PtrToString(a.FriendlyName),
			Description: utf16PtrToString(a.Description),
			MTU:         int(a.Mtu),
			Up:          a.OperStatus == windows.IfOperStatusUp,
			Running:     a.OperStatus == windows.IfOperStatusUp,
		}
		if iface.Name == "" {
			iface.Name = fmt.Sprintf("if%d", a.IfIndex)
		}
		if n := int(a.PhysicalAddressLength); n > 0 && n <= len(a.PhysicalAddress) {
			parts := make([]string, 0, n)
			for i := 0; i < n; i++ {
				parts = append(parts, fmt.Sprintf("%02x", a.PhysicalAddress[i]))
			}
			iface.MAC = strings.Join(parts, ":")
		}
		iface.Type = classifyWindowsInterface(a.IfType, iface.Name)

		for ua := a.FirstUnicastAddress; ua != nil; ua = ua.Next {
			addr, ok := sockaddrToAddr(ua.Address)
			if !ok {
				continue
			}
			bits := int(ua.OnLinkPrefixLength)
			if bits <= 0 || bits > addr.BitLen() {
				bits = addr.BitLen()
			}
			iface.Addrs = append(iface.Addrs, netip.PrefixFrom(addr, bits))
		}

		row := windows.MibIfRow2{InterfaceIndex: a.IfIndex}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err == nil {
			iface.Counters = types.Counters{
				RxBytes:   row.InOctets,
				TxBytes:   row.OutOctets,
				RxPackets: row.InUcastPkts + row.InNUcastPkts,
				TxPackets: row.OutUcastPkts + row.OutNUcastPkts,
				RxErrors:  row.InErrors,
				TxErrors:  row.OutErrors,
				RxDropped: row.InDiscards,
				TxDropped: row.OutDiscards,
			}
			if row.ReceiveLinkSpeed > 0 {
				iface.SpeedMbps = int(row.ReceiveLinkSpeed / 1_000_000)
			}
			if row.TransmitLinkSpeed > 0 {
				if s := int(row.TransmitLinkSpeed / 1_000_000); s > 0 && s < iface.SpeedMbps {
					iface.SpeedMbps = s
				}
			}
			// MediaConnectState 1 means connected: this is the Windows equivalent of
			// carrier detection, and it is what separates "adapter enabled" from
			// "cable plugged in".
			iface.Running = row.MediaConnectState == 1
		} else if a.TransmitLinkSpeed > 0 && a.TransmitLinkSpeed != ^uint64(0) {
			iface.SpeedMbps = int(a.TransmitLinkSpeed / 1_000_000)
		}
		out = append(out, iface)
	}
	return out, nil
}

func classifyWindowsInterface(ifType uint32, name string) string {
	switch ifType {
	case ifTypeSoftwareLoop:
		return types.IfaceLoopback
	case ifTypeIEEE80211:
		return types.IfaceWireless
	case ifTypeEthernetCSMACD:
		// Many virtual adapters present as Ethernet, so fall through to name-based
		// classification to separate real NICs from Hyper-V, WSL and VPN adapters.
		return types.ClassifyInterface(name, false, false, false)
	case ifTypePPP, ifTypeTunnel:
		return types.IfaceTunnel
	case ifTypeOther:
		return types.ClassifyInterface(name, false, false, false)
	}
	return types.ClassifyInterface(name, false, false, false)
}

// adapterAddresses calls GetAdaptersAddresses, growing the buffer as required.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_PREFIX |
		windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	size := uint32(32 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			// size now holds the required length; retry with the bigger buffer.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("windows: GetAdaptersAddresses: %w", err)
		}
		var out []*windows.IpAdapterAddresses
		for a := first; a != nil; a = a.Next {
			out = append(out, a)
		}
		// The returned pointers alias buf, which stays alive through out.
		return out, nil
	}
	return nil, fmt.Errorf("windows: GetAdaptersAddresses: buffer kept growing")
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// sockaddrToAddr converts a Win32 SOCKET_ADDRESS to a netip.Addr.
func sockaddrToAddr(sa windows.SocketAddress) (netip.Addr, bool) {
	if sa.Sockaddr == nil {
		return netip.Addr{}, false
	}
	switch sa.Sockaddr.Addr.Family {
	case windows.AF_INET:
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom4(v4.Addr), true
	case windows.AF_INET6:
		v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		addr := netip.AddrFrom16(v6.Addr)
		if v6.Scope_id != 0 && (addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()) {
			addr = addr.WithZone(fmt.Sprint(v6.Scope_id))
		}
		return addr.Unmap(), true
	}
	return netip.Addr{}, false
}
