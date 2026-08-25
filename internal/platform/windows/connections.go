//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP_TABLE_CLASS / UDP_TABLE_CLASS values used here.
const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID: six DWORDs, no padding.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6RowOwnerPID mirrors MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUDPRowOwnerPID mirrors MIB_UDPROW_OWNER_PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// mibUDP6RowOwnerPID mirrors MIB_UDP6ROW_OWNER_PID.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// Windows MIB_TCP_STATE values.
var tcpStates = map[uint32]string{
	1:  types.StateClosed,
	2:  types.StateListen,
	3:  types.StateSynSent,
	4:  types.StateSynRecv,
	5:  types.StateEstablished,
	6:  types.StateFinWait1,
	7:  types.StateFinWait2,
	8:  types.StateCloseWait,
	9:  types.StateClosing,
	10: types.StateLastAck,
	11: types.StateTimeWait,
	12: types.StateDeleteTCB,
}

// Connections reads the extended TCP and UDP tables, which include the owning process
// id for every socket on the system. Unlike the Linux path there is no inode lookup:
// Windows hands over the PID directly.
func (p *Provider) Connections(opts types.ConnOptions) ([]types.Connection, error) {
	if !opts.TCP && !opts.UDP {
		opts.TCP = true
	}
	var conns []types.Connection

	if opts.TCP {
		v4, err := tcpTable(windows.AF_INET)
		if err == nil {
			conns = append(conns, v4...)
		}
		v6, err6 := tcpTable(windows.AF_INET6)
		if err6 == nil {
			conns = append(conns, v6...)
		}
		if err != nil && err6 != nil {
			return nil, err
		}
	}
	if opts.UDP {
		v4, _ := udpTable(windows.AF_INET)
		conns = append(conns, v4...)
		v6, _ := udpTable(windows.AF_INET6)
		conns = append(conns, v6...)
	}

	filtered := conns[:0]
	for _, c := range conns {
		if c.State == types.StateListen && !opts.IncludeListening {
			continue
		}
		if c.Protocol == "udp" && (c.Remote.Addr().IsUnspecified() || c.Remote.Port() == 0) && !opts.IncludeListening {
			continue
		}
		if !opts.IncludeLoopback && (c.Local.Addr().IsLoopback() || c.Remote.Addr().IsLoopback()) {
			continue
		}
		filtered = append(filtered, c)
	}
	conns = filtered

	if opts.ResolveProcess {
		cache := map[int]types.Process{}
		for i := range conns {
			pid := conns[i].PID
			if pid <= 0 {
				continue
			}
			proc, ok := cache[pid]
			if !ok {
				proc, _ = processInfo(pid)
				cache[pid] = proc
			}
			conns[i].Process = proc.Name
			conns[i].Exe = proc.Exe
			conns[i].User = proc.User
		}
	}
	if opts.Max > 0 && len(conns) > opts.Max {
		conns = conns[:opts.Max]
	}
	return conns, nil
}

// extendedTable calls one of the GetExtended*Table functions, growing the buffer until
// it fits, and returns the raw bytes.
func extendedTable(proc *windows.LazyProc, family uint32, class uintptr, udp bool) ([]byte, error) {
	size := uint32(64 * 1024)
	protocol := uintptr(6) // IPPROTO_TCP
	if udp {
		protocol = 17 // IPPROTO_UDP
	}
	for attempt := 0; attempt < 6; attempt++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder = FALSE: iPulse does not need sorted output
			uintptr(family),
			class,
			protocol,
		)
		switch r {
		case 0:
			return buf, nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			// size now holds the required length.
			size += 4096
			continue
		default:
			return nil, fmt.Errorf("windows: %s failed: %w", proc.Name, windows.Errno(r))
		}
	}
	return nil, fmt.Errorf("windows: %s: table kept growing", proc.Name)
}

func tcpTable(family uint32) ([]types.Connection, error) {
	buf, err := extendedTable(procGetExtendedTCPTable, family, tcpTableOwnerPIDAll, false)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	var out []types.Connection

	if family == windows.AF_INET {
		rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		for i := 0; i < int(n); i++ {
			off := 4 + i*rowSize
			if off+rowSize > len(buf) {
				break
			}
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, types.Connection{
				Protocol: "tcp",
				Local:    netip.AddrPortFrom(addrFromDWORD(row.LocalAddr), portFromDWORD(row.LocalPort)),
				Remote:   netip.AddrPortFrom(addrFromDWORD(row.RemoteAddr), portFromDWORD(row.RemotePort)),
				State:    tcpStateName(row.State),
				PID:      int(row.OwningPID),
			})
		}
		return out, nil
	}

	rowSize := int(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	for i := 0; i < int(n); i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[off]))
		out = append(out, types.Connection{
			Protocol: "tcp",
			Local:    netip.AddrPortFrom(netip.AddrFrom16(row.LocalAddr).Unmap(), portFromDWORD(row.LocalPort)),
			Remote:   netip.AddrPortFrom(netip.AddrFrom16(row.RemoteAddr).Unmap(), portFromDWORD(row.RemotePort)),
			State:    tcpStateName(row.State),
			PID:      int(row.OwningPID),
		})
	}
	return out, nil
}

func udpTable(family uint32) ([]types.Connection, error) {
	buf, err := extendedTable(procGetExtendedUDPTable, family, udpTableOwnerPID, true)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	var out []types.Connection

	if family == windows.AF_INET {
		rowSize := int(unsafe.Sizeof(mibUDPRowOwnerPID{}))
		for i := 0; i < int(n); i++ {
			off := 4 + i*rowSize
			if off+rowSize > len(buf) {
				break
			}
			row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, types.Connection{
				Protocol: "udp",
				Local:    netip.AddrPortFrom(addrFromDWORD(row.LocalAddr), portFromDWORD(row.LocalPort)),
				State:    types.StateNone,
				PID:      int(row.OwningPID),
			})
		}
		return out, nil
	}

	rowSize := int(unsafe.Sizeof(mibUDP6RowOwnerPID{}))
	for i := 0; i < int(n); i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[off]))
		out = append(out, types.Connection{
			Protocol: "udp",
			Local:    netip.AddrPortFrom(netip.AddrFrom16(row.LocalAddr).Unmap(), portFromDWORD(row.LocalPort)),
			State:    types.StateNone,
			PID:      int(row.OwningPID),
		})
	}
	return out, nil
}

func tcpStateName(state uint32) string {
	if s, ok := tcpStates[state]; ok {
		return s
	}
	return types.StateNone
}

// addrFromDWORD converts an in_addr (already in network byte order) to a netip.Addr.
func addrFromDWORD(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// portFromDWORD extracts a port from the DWORD the API returns: the value sits in the
// low 16 bits in network byte order.
func portFromDWORD(v uint32) uint16 {
	b := []byte{byte(v), byte(v >> 8)}
	return binary.BigEndian.Uint16(b)
}
