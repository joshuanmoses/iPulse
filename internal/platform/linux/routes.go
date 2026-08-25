//go:build linux

package linux

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Routes reads the IPv4 and IPv6 routing tables from /proc. Both files are the kernel's
// own rendering of the FIB, so no external tool is involved.
func (p *Provider) Routes() ([]types.Route, error) {
	v4, err4 := readRoutesV4(procNetRoute)
	v6, err6 := readRoutesV6(procNetIPv6)
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("linux: cannot read routing table: %w", err4)
	}
	return append(v4, v6...), nil
}

// readRoutesV4 parses /proc/net/route. Addresses are hex in host byte order, which on
// every platform Linux supports in practice means little-endian.
func readRoutesV4(path string) ([]types.Route, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []types.Route
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first { // header
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		dest, ok := hexLEToAddr4(fields[1])
		if !ok {
			continue
		}
		gw, _ := hexLEToAddr4(fields[2])
		maskBits, ok := hexLEToMaskBits(fields[7])
		if !ok {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		prefix := netip.PrefixFrom(dest, maskBits)
		r := types.Route{
			Destination: prefix,
			Interface:   fields[0],
			Metric:      metric,
			Default:     maskBits == 0 && dest.IsUnspecified(),
		}
		if gw.IsValid() && !gw.IsUnspecified() {
			r.Gateway = gw
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// readRoutesV6 parses /proc/net/ipv6_route.
func readRoutesV6(path string) ([]types.Route, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []types.Route
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		dest, ok := hexToAddr16(fields[0])
		if !ok {
			continue
		}
		plen, err := strconv.ParseInt(fields[1], 16, 32)
		if err != nil {
			continue
		}
		nexthop, _ := hexToAddr16(fields[4])
		metric, _ := strconv.ParseInt(fields[5], 16, 32)
		iface := fields[9]

		r := types.Route{
			Destination: netip.PrefixFrom(dest, int(plen)),
			Interface:   iface,
			Metric:      int(metric),
			Default:     plen == 0 && dest.IsUnspecified(),
		}
		if nexthop.IsValid() && !nexthop.IsUnspecified() {
			r.Gateway = nexthop
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func hexLEToAddr4(s string) (netip.Addr, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), true
}

func hexLEToMaskBits(s string) (int, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	mask := binary.BigEndian.Uint32(b[:])
	bits := 0
	for i := 31; i >= 0; i-- {
		if mask&(1<<uint(i)) == 0 {
			break
		}
		bits++
	}
	return bits, true
}

func hexToAddr16(s string) (netip.Addr, bool) {
	if len(s) != 32 {
		return netip.Addr{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a).Unmap(), true
}
