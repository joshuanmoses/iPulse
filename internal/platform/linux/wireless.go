//go:build linux

package linux

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Wireless-extensions ioctls. The cfg80211 WEXT compatibility layer is enabled in
// essentially every distribution kernel, and these five requests give SSID, BSSID, bit
// rate and frequency without cgo, without libnl and without shelling out to iw.
//
// Deliberately absent: anything that could read credentials. iPulse reads association
// metadata only, never keys or passphrases.
const (
	siocGIWNAME  = 0x8B01
	siocGIWFREQ  = 0x8B05
	siocGIWAP    = 0x8B15
	siocGIWESSID = 0x8B1B
	siocGIWRATE  = 0x8B21
)

// ifnameSize is IFNAMSIZ.
const ifnameSize = 16

// iwreq mirrors struct iwreq: a 16-byte interface name followed by a union. The union
// is modelled as an opaque byte array so field offsets are explicit and no Go struct
// alignment rule can shift them, and it is oversized so the kernel's copy_from_user of
// sizeof(struct iwreq) can never read past our buffer.
type iwreq struct {
	name [ifnameSize]byte
	data [32]byte
}

func newIwreq(iface string) (*iwreq, error) {
	if len(iface) >= ifnameSize {
		return nil, fmt.Errorf("linux: interface name %q is too long", iface)
	}
	r := &iwreq{}
	copy(r.name[:], iface)
	return r, nil
}

func ioctlIw(fd int, req uintptr, r *iwreq) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(r)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Wireless returns telemetry for every associated wireless interface.
//
// Two mechanisms are tried in order:
//
//  1. nl80211 over netlink. This is the modern kernel API and the only one available on
//     many current distributions, where the wireless-extensions compatibility layer is
//     compiled out. It provides SSID, BSSID, signal strength, negotiated rates and
//     frequency.
//  2. The wireless-extensions ioctls plus /proc/net/wireless, for older kernels and
//     drivers that still expose them.
//
// Neither path reads credentials, keys or profiles.
func (p *Provider) Wireless() ([]types.WirelessLink, error) {
	if links, err := nl80211Links(); err == nil && len(links) > 0 {
		return links, nil
	}
	return wextLinks()
}

// wextLinks is the wireless-extensions fallback.
func wextLinks() ([]types.WirelessLink, error) {
	ifaces, err := wirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		return nil, types.ErrUnsupported
	}
	stats := readProcWireless()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("linux: wireless socket: %w", err)
	}
	defer syscall.Close(fd)

	var out []types.WirelessLink
	for _, name := range ifaces {
		link := types.WirelessLink{Interface: name}
		if s, ok := stats[name]; ok {
			link.SignalDBM = s.levelDBM
			link.NoiseDBM = s.noiseDBM
		}
		if ssid, err := getESSID(fd, name); err == nil {
			link.SSID = ssid
		}
		if bssid, err := getAP(fd, name); err == nil {
			link.BSSID = bssid
		}
		if rate, err := getBitRate(fd, name); err == nil {
			link.LinkMbps = rate
		}
		if mhz, err := getFrequency(fd, name); err == nil {
			link.FrequencyMHz = mhz
			link.Channel = types.ChannelForFrequency(mhz)
			link.Band = types.BandForFrequency(mhz)
		}
		if link.SignalDBM != 0 {
			link.SignalPct = types.SignalPercent(link.SignalDBM)
		}
		// Report only associated interfaces: an idle radio has no useful telemetry and
		// would otherwise look like a permanently degraded link.
		if link.SSID == "" && link.SignalDBM == 0 {
			continue
		}
		out = append(out, link)
	}
	if len(out) == 0 {
		return nil, types.ErrNotFound
	}
	return out, nil
}

func getESSID(fd int, iface string) (string, error) {
	r, err := newIwreq(iface)
	if err != nil {
		return "", err
	}
	// struct iw_point { void *pointer; __u16 length; __u16 flags; } at union offset 0.
	buf := make([]byte, 33) // IW_ESSID_MAX_SIZE + 1
	binary.NativeEndian.PutUint64(r.data[0:8], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	binary.NativeEndian.PutUint16(r.data[8:10], uint16(len(buf)))
	binary.NativeEndian.PutUint16(r.data[10:12], 0)

	if err := ioctlIw(fd, siocGIWESSID, r); err != nil {
		return "", err
	}
	// Keep buf alive across the ioctl.
	n := int(binary.NativeEndian.Uint16(r.data[8:10]))
	if n > len(buf) {
		n = len(buf)
	}
	ssid := strings.TrimRight(string(buf[:n]), "\x00")
	runtimeKeepAlive(&buf)
	return sanitizeSSID(ssid), nil
}

// sanitizeSSID strips control characters. An SSID is attacker-controlled input that
// ends up in logs and in the dashboard, so it is cleaned at the source as well.
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

func getAP(fd int, iface string) (string, error) {
	r, err := newIwreq(iface)
	if err != nil {
		return "", err
	}
	if err := ioctlIw(fd, siocGIWAP, r); err != nil {
		return "", err
	}
	// struct sockaddr { __u16 sa_family; char sa_data[14]; } - MAC in the first 6 bytes.
	mac := r.data[2:8]
	if allZero(mac) {
		return "", types.ErrNotFound
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}

func getBitRate(fd int, iface string) (float64, error) {
	r, err := newIwreq(iface)
	if err != nil {
		return 0, err
	}
	if err := ioctlIw(fd, siocGIWRATE, r); err != nil {
		return 0, err
	}
	// struct iw_param { __s32 value; ... } - value is bits per second.
	bps := int32(binary.NativeEndian.Uint32(r.data[0:4]))
	if bps <= 0 {
		return 0, types.ErrNotFound
	}
	return float64(bps) / 1e6, nil
}

func getFrequency(fd int, iface string) (int, error) {
	r, err := newIwreq(iface)
	if err != nil {
		return 0, err
	}
	if err := ioctlIw(fd, siocGIWFREQ, r); err != nil {
		return 0, err
	}
	// struct iw_freq { __s32 m; __s16 e; __u8 i; __u8 flags; } - value is m * 10^e Hz.
	m := int64(int32(binary.NativeEndian.Uint32(r.data[0:4])))
	e := int16(binary.NativeEndian.Uint16(r.data[4:6]))
	if e == 0 {
		// Some drivers report a channel number instead of a frequency.
		if m > 0 && m < 200 {
			return channelToFrequency(int(m)), nil
		}
		return int(m / 1e6), nil
	}
	hz := float64(m)
	for i := int16(0); i < e; i++ {
		hz *= 10
	}
	return int(hz / 1e6), nil
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

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

type wirelessStat struct {
	linkQuality int
	levelDBM    int
	noiseDBM    int
}

// readProcWireless parses /proc/net/wireless, which cfg80211 populates for every
// modern driver. This is the signal-strength source that works even where the WEXT
// ioctls above are compiled out.
func readProcWireless() map[string]wirelessStat {
	out := map[string]wirelessStat{}
	f, err := os.Open(procNetWless)
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		if line <= 2 { // two header lines
			continue
		}
		text := sc.Text()
		colon := strings.IndexByte(text, ':')
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(text[:colon])
		fields := strings.Fields(text[colon+1:])
		if len(fields) < 4 {
			continue
		}
		st := wirelessStat{
			linkQuality: parseWirelessValue(fields[1]),
			levelDBM:    normaliseDBM(parseWirelessValue(fields[2])),
			noiseDBM:    normaliseDBM(parseWirelessValue(fields[3])),
		}
		out[iface] = st
	}
	return out
}

// parseWirelessValue handles the trailing '.' the kernel appends to these columns.
func parseWirelessValue(s string) int {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

// normaliseDBM converts the unsigned form some drivers report (dBm + 256) into a
// signed dBm value.
func normaliseDBM(v int) int {
	if v > 0 {
		return v - 256
	}
	return v
}

// runtimeKeepAlive keeps a buffer reachable until after the ioctl has written into it.
func runtimeKeepAlive(p *[]byte) { _ = (*p)[0] }
