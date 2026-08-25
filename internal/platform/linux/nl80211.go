//go:build linux

package linux

import (
	"fmt"
	"sort"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// nl80211 command and attribute identifiers, from the kernel's nl80211.h. Only the
// read-only subset iPulse needs is declared: interface state, station statistics and
// cached scan results. No command that changes radio state is present.
const (
	nl80211CmdGetInterface = 5
	nl80211CmdGetStation   = 17
	nl80211CmdGetScan      = 32

	nl80211AttrIfIndex   = 3
	nl80211AttrIfName    = 4
	nl80211AttrIfType    = 5
	nl80211AttrMAC       = 6
	nl80211AttrStaInfo   = 21
	nl80211AttrWiphyFreq = 38
	nl80211AttrSSID      = 52
	nl80211AttrBSS       = 47

	nl80211IfTypeStation = 2

	staInfoSignal    = 7
	staInfoTxBitrate = 8
	staInfoSignalAvg = 13
	staInfoRxBitrate = 14

	rateInfoBitrate   = 1
	rateInfoBitrate32 = 5

	bssBSSID     = 1
	bssFreq      = 2
	bssIEs       = 6
	bssSignal    = 7
	bssStatus    = 9
	bssBeaconIEs = 11

	bssStatusAssociated = 1

	ieSSID = 0
)

// nl80211Links collects wireless telemetry over netlink. This is the primary path on
// modern kernels, where the wireless-extensions ioctls and /proc/net/wireless are often
// compiled out entirely.
func nl80211Links() ([]types.WirelessLink, error) {
	conn, err := dialGenetlink()
	if err != nil {
		return nil, err
	}
	defer conn.close()

	family, err := conn.resolveFamily("nl80211")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrUnsupported, err)
	}

	// Step 1: enumerate wireless interfaces in station (client) mode.
	replies, err := conn.request(family, nl80211CmdGetInterface, true, nil)
	if err != nil {
		return nil, err
	}
	type ifaceInfo struct {
		index int
		name  string
		ssid  string
		freq  int
	}
	var ifaces []ifaceInfo
	for _, r := range replies {
		attrs, err := parseAttrs(r)
		if err != nil {
			continue
		}
		name := attrString(attrs[nl80211AttrIfName])
		if name == "" {
			continue
		}
		if t, ok := attrs[nl80211AttrIfType]; ok && attrU32(t) != nl80211IfTypeStation {
			continue
		}
		info := ifaceInfo{index: int(attrU32(attrs[nl80211AttrIfIndex])), name: name}
		if v, ok := attrs[nl80211AttrSSID]; ok {
			info.ssid = sanitizeSSID(string(v))
		}
		if v, ok := attrs[nl80211AttrWiphyFreq]; ok {
			info.freq = int(attrU32(v))
		}
		ifaces = append(ifaces, info)
	}
	if len(ifaces) == 0 {
		return nil, types.ErrNotFound
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].name < ifaces[j].name })

	var out []types.WirelessLink
	for _, info := range ifaces {
		link := types.WirelessLink{Interface: info.name, SSID: info.ssid, FrequencyMHz: info.freq}

		// Step 2: station statistics give signal strength and negotiated bit rates.
		// For a client interface the only "station" is the access point.
		if bssid, signal, tx, rx, ok := stationInfo(conn, family, info.index); ok {
			link.BSSID = bssid
			link.SignalDBM = signal
			link.LinkMbps = tx
			link.RxMbps = rx
		}

		// Step 3: the cached scan tells us the SSID and frequency of the BSS we are
		// associated with, for drivers that do not report SSID on the interface.
		if link.SSID == "" || link.FrequencyMHz == 0 || link.SignalDBM == 0 {
			if ssid, freq, signal, bssid, ok := associatedBSS(conn, family, info.index); ok {
				if link.SSID == "" {
					link.SSID = ssid
				}
				if link.FrequencyMHz == 0 {
					link.FrequencyMHz = freq
				}
				if link.SignalDBM == 0 {
					link.SignalDBM = signal
				}
				if link.BSSID == "" {
					link.BSSID = bssid
				}
			}
		}

		if link.SSID == "" && link.SignalDBM == 0 {
			continue // radio up but not associated
		}
		if link.FrequencyMHz > 0 {
			link.Channel = types.ChannelForFrequency(link.FrequencyMHz)
			link.Band = types.BandForFrequency(link.FrequencyMHz)
		}
		if link.SignalDBM != 0 {
			link.SignalPct = types.SignalPercent(link.SignalDBM)
		}
		out = append(out, link)
	}
	if len(out) == 0 {
		return nil, types.ErrNotFound
	}
	return out, nil
}

// stationInfo returns BSSID, signal in dBm and tx/rx rates in Mbps for the AP a client
// interface is associated with.
func stationInfo(conn *genlConn, family uint16, ifIndex int) (bssid string, signalDBM int, txMbps, rxMbps float64, ok bool) {
	attrs := putAttrU32(nil, nl80211AttrIfIndex, uint32(ifIndex))
	replies, err := conn.request(family, nl80211CmdGetStation, true, attrs)
	if err != nil {
		return "", 0, 0, 0, false
	}
	for _, r := range replies {
		top, err := parseAttrs(r)
		if err != nil {
			continue
		}
		mac := top[nl80211AttrMAC]
		sta, hasSta := top[nl80211AttrStaInfo]
		if !hasSta {
			continue
		}
		info, err := parseAttrs(sta)
		if err != nil {
			continue
		}
		if len(mac) >= 6 {
			bssid = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
		// SIGNAL_AVG is smoothed and therefore a better input to a baseline than the
		// instantaneous value; fall back to SIGNAL when the driver omits it.
		if v, has := info[staInfoSignalAvg]; has {
			signalDBM = int(attrS8(v))
		} else if v, has := info[staInfoSignal]; has {
			signalDBM = int(attrS8(v))
		}
		txMbps = rateFromNested(info[staInfoTxBitrate])
		rxMbps = rateFromNested(info[staInfoRxBitrate])
		return bssid, signalDBM, txMbps, rxMbps, true
	}
	return "", 0, 0, 0, false
}

// rateFromNested decodes a nested NL80211_RATE_INFO attribute. Rates are in units of
// 100 kbps; the 32-bit form is preferred because 802.11ac/ax rates overflow the 16-bit
// field.
func rateFromNested(nested []byte) float64 {
	if len(nested) == 0 {
		return 0
	}
	attrs, err := parseAttrs(nested)
	if err != nil {
		return 0
	}
	if v, ok := attrs[rateInfoBitrate32]; ok && len(v) >= 4 {
		return float64(attrU32(v)) / 10
	}
	if v, ok := attrs[rateInfoBitrate]; ok && len(v) >= 2 {
		return float64(attrU16(v)) / 10
	}
	return 0
}

// associatedBSS reads the cached scan results and returns details of the BSS this
// interface is associated with. Reading cached results does not trigger a scan, so it
// costs no airtime.
func associatedBSS(conn *genlConn, family uint16, ifIndex int) (ssid string, freq, signalDBM int, bssid string, ok bool) {
	attrs := putAttrU32(nil, nl80211AttrIfIndex, uint32(ifIndex))
	replies, err := conn.request(family, nl80211CmdGetScan, true, attrs)
	if err != nil {
		return "", 0, 0, "", false
	}
	for _, r := range replies {
		top, err := parseAttrs(r)
		if err != nil {
			continue
		}
		bssAttr, has := top[nl80211AttrBSS]
		if !has {
			continue
		}
		bss, err := parseAttrs(bssAttr)
		if err != nil {
			continue
		}
		status, hasStatus := bss[bssStatus]
		if !hasStatus || attrU32(status) != bssStatusAssociated {
			continue
		}
		if v, has := bss[bssBSSID]; has && len(v) >= 6 {
			bssid = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5])
		}
		if v, has := bss[bssFreq]; has {
			freq = int(attrU32(v))
		}
		if v, has := bss[bssSignal]; has {
			// SIGNAL_MBM is in mBm: hundredths of a dBm.
			signalDBM = int(attrS32(v) / 100)
		}
		ies := bss[bssIEs]
		if len(ies) == 0 {
			ies = bss[bssBeaconIEs]
		}
		ssid = sanitizeSSID(ssidFromIEs(ies))
		return ssid, freq, signalDBM, bssid, true
	}
	return "", 0, 0, "", false
}

// ssidFromIEs extracts the SSID from an 802.11 information-element blob. Elements are
// {id, length, value} triples; only element 0 (SSID) is read, and nothing else in the
// blob is interpreted.
func ssidFromIEs(ies []byte) string {
	for len(ies) >= 2 {
		id := ies[0]
		length := int(ies[1])
		if 2+length > len(ies) {
			return ""
		}
		if id == ieSSID {
			return string(ies[2 : 2+length])
		}
		ies = ies[2+length:]
	}
	return ""
}
