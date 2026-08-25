//go:build windows

package windows

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

var (
	modwlanapi             = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = modwlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modwlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modwlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modwlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = modwlanapi.NewProc("WlanFreeMemory")
)

// WLAN_INTF_OPCODE values.
const (
	wlanIntfOpcodeCurrentConnection = 7
	wlanIntfOpcodeChannelNumber     = 8
)

// wlanInterfaceInfo mirrors WLAN_INTERFACE_INFO.
type wlanInterfaceInfo struct {
	InterfaceGUID        windows.GUID
	InterfaceDescription [256]uint16
	State                uint32
}

// wlanInterfaceInfoList mirrors WLAN_INTERFACE_INFO_LIST (header then a flexible array).
type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	InterfaceInfo [1]wlanInterfaceInfo
}

// dot11SSID mirrors DOT11_SSID.
type dot11SSID struct {
	SSIDLength uint32
	SSID       [32]byte
}

// wlanAssociationAttributes mirrors WLAN_ASSOCIATION_ATTRIBUTES. Field order and
// padding match the SDK: the 6-byte BSSID is followed by two bytes of padding before
// the next 4-byte member, which Go inserts automatically for the same field types.
type wlanAssociationAttributes struct {
	SSID          dot11SSID
	BSSType       uint32
	BSSID         [6]uint8
	PhyType       uint32
	PhyIndex      uint32
	SignalQuality uint32
	RxRate        uint32
	TxRate        uint32
}

// wlanConnectionAttributes mirrors WLAN_CONNECTION_ATTRIBUTES.
//
// Only association metadata is read. The security attributes that follow in the SDK
// structure are deliberately not declared: iPulse never reads authentication or cipher
// state, and never touches profile XML, which is where credentials would live.
type wlanConnectionAttributes struct {
	InterfaceState        uint32
	ConnectionMode        uint32
	ProfileName           [256]uint16
	AssociationAttributes wlanAssociationAttributes
}

// wlanInterfaceStateConnected is WLAN_INTERFACE_STATE wlan_interface_state_connected.
const wlanInterfaceStateConnected = 1

// Wireless returns telemetry for connected wireless interfaces using the native WLAN
// API. Signal quality is reported by Windows as 0-100; the documented mapping onto RSSI
// is linear from -100 dBm to -50 dBm, which is applied here so both platforms report
// the same unit.
func (p *Provider) Wireless() ([]types.WirelessLink, error) {
	if err := modwlanapi.Load(); err != nil {
		return nil, fmt.Errorf("%w: wlanapi.dll unavailable", types.ErrUnsupported)
	}
	var negotiated uint32
	var handle windows.Handle
	r, _, _ := procWlanOpenHandle.Call(2, 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if r != 0 {
		return nil, fmt.Errorf("windows: WlanOpenHandle: %w (is the WLAN AutoConfig service running?)", windows.Errno(r))
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)

	var listPtr *wlanInterfaceInfoList
	r, _, _ = procWlanEnumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 {
		return nil, fmt.Errorf("windows: WlanEnumInterfaces: %w", windows.Errno(r))
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(listPtr)))
	if listPtr == nil || listPtr.NumberOfItems == 0 {
		return nil, types.ErrNotFound
	}

	// Map adapter GUIDs to friendly names so the reported interface matches the name
	// used everywhere else in iPulse.
	nameByGUID := map[string]string{}
	if adapters, err := adapterAddresses(); err == nil {
		for _, a := range adapters {
			if a.AdapterName == nil {
				continue
			}
			guid := strings.ToUpper(bytePtrToString(a.AdapterName))
			nameByGUID[guid] = utf16PtrToString(a.FriendlyName)
		}
	}

	infos := unsafe.Slice(&listPtr.InterfaceInfo[0], int(listPtr.NumberOfItems))
	var out []types.WirelessLink
	for i := range infos {
		info := infos[i]
		if info.State != wlanInterfaceStateConnected {
			continue
		}
		name := nameByGUID[strings.ToUpper(guidString(info.InterfaceGUID))]
		if name == "" {
			name = strings.TrimRight(windows.UTF16ToString(info.InterfaceDescription[:]), "\x00")
		}
		link := types.WirelessLink{Interface: name}

		conn, err := queryConnection(handle, info.InterfaceGUID)
		if err != nil {
			continue
		}
		assoc := conn.AssociationAttributes
		n := int(assoc.SSID.SSIDLength)
		if n > len(assoc.SSID.SSID) {
			n = len(assoc.SSID.SSID)
		}
		link.SSID = sanitizeSSID(string(assoc.SSID.SSID[:n]))
		link.BSSID = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			assoc.BSSID[0], assoc.BSSID[1], assoc.BSSID[2], assoc.BSSID[3], assoc.BSSID[4], assoc.BSSID[5])
		link.SignalPct = int(assoc.SignalQuality)
		link.SignalDBM = qualityToDBM(int(assoc.SignalQuality))
		// The WLAN API documents ulTxRate and ulRxRate in kbps.
		link.LinkMbps = float64(assoc.TxRate) / 1000
		link.RxMbps = float64(assoc.RxRate) / 1000

		if ch, err := queryChannel(handle, info.InterfaceGUID); err == nil && ch > 0 {
			link.Channel = int(ch)
			link.FrequencyMHz = channelToFrequency(int(ch))
			link.Band = types.BandForFrequency(link.FrequencyMHz)
		}
		out = append(out, link)
	}
	if len(out) == 0 {
		return nil, types.ErrNotFound
	}
	return out, nil
}

func queryConnection(handle windows.Handle, guid windows.GUID) (*wlanConnectionAttributes, error) {
	var size uint32
	var data *wlanConnectionAttributes
	var valueType uint32
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&valueType)),
	)
	if r != 0 || data == nil {
		return nil, fmt.Errorf("windows: WlanQueryInterface(current_connection): %w", windows.Errno(r))
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))
	// Copy out before the API-allocated buffer is freed.
	out := *data
	return &out, nil
}

func queryChannel(handle windows.Handle, guid windows.GUID) (uint32, error) {
	var size uint32
	var data *uint32
	var valueType uint32
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(wlanIntfOpcodeChannelNumber),
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&valueType)),
	)
	if r != 0 || data == nil {
		return 0, fmt.Errorf("windows: WlanQueryInterface(channel_number): %w", windows.Errno(r))
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))
	return *data, nil
}

// qualityToDBM converts the Windows 0-100 signal quality to RSSI in dBm using the
// mapping documented for WLAN_SIGNAL_QUALITY.
func qualityToDBM(quality int) int {
	if quality <= 0 {
		return -100
	}
	if quality >= 100 {
		return -50
	}
	return -100 + quality/2
}

func channelToFrequency(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	case ch >= 32 && ch <= 177:
		return 5000 + ch*5
	}
	return 0
}

// sanitizeSSID strips control characters from an attacker-controlled SSID before it
// reaches logs or the dashboard.
func sanitizeSSID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func guidString(g windows.GUID) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

func bytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	return windows.BytePtrToString(p)
}
