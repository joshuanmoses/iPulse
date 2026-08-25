package util

import (
	"net/netip"
	"strings"
)

// privateRanges are the address ranges iPulse treats as "internal": traffic to them is
// lateral movement within the site, not Internet activity.
//
// The list deliberately goes beyond RFC 1918. Carrier-grade NAT space, link-local,
// unique-local IPv6 and the IPv4-mapped forms all describe traffic that never reaches
// the public Internet, and treating them as external would produce a stream of
// meaningless "new external destination" reports on any normal network.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("255.255.255.255/32"),

	netip.MustParsePrefix("::1/128"),   // loopback
	netip.MustParsePrefix("fc00::/7"),  // unique local
	netip.MustParsePrefix("fe80::/10"), // link-local
	netip.MustParsePrefix("ff00::/8"),  // multicast
}

// documentationRanges are reserved for documentation and examples. They are public in
// the routing sense but never real destinations, which matters when interpreting test
// data and sample configurations.
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// IsPrivateAddr reports whether an address is inside the local network, loopback,
// link-local, CGNAT or multicast space.
func IsPrivateAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range privateRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsDocumentationAddr reports whether an address is in a reserved documentation range.
func IsDocumentationAddr(addr netip.Addr) bool {
	a := addr.Unmap()
	for _, p := range documentationRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsInternal reports whether an address is internal, taking site-specific extra ranges
// into account. Sites routinely use ranges that are technically public but are in fact
// their own, so this is configurable.
func IsInternal(addr netip.Addr, extra []netip.Prefix) bool {
	if IsPrivateAddr(addr) {
		return true
	}
	a := addr.Unmap()
	for _, p := range extra {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses CIDR strings, returning the ones that parsed and the ones that
// did not, so a configuration error names the offending entry instead of failing wholesale.
func ParsePrefixes(in []string) (out []netip.Prefix, invalid []string) {
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// A bare address is accepted as a single-host prefix, which is what an
			// operator listing one IP means.
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			invalid = append(invalid, s)
			continue
		}
		out = append(out, p.Masked())
	}
	return out, invalid
}

// MatchesAnyPrefix reports whether the address is inside any of the prefixes.
func MatchesAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	a := addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MatchGlob is a minimal case-insensitive glob supporting '*' anywhere, used for
// interface and process name patterns in the configuration. A full regular-expression
// syntax would be more power than an operator needs here, and easier to get wrong.
func MatchGlob(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	if pattern == "" {
		return s == ""
	}
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	// Anchor the first and last segments, and scan for the middle ones in order.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	rest := s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(rest, parts[i])
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(parts[i]):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(rest, last) || last == ""
}

// MatchesAnyGlob reports whether s matches any of the patterns.
func MatchesAnyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if MatchGlob(p, s) {
			return true
		}
	}
	return false
}
