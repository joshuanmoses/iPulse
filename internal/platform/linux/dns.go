//go:build linux

package linux

import (
	"bufio"
	"net/netip"
	"os"
	"strings"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// DNSServers reads the configured resolvers from /etc/resolv.conf.
//
// On systemd-resolved hosts that file usually contains only 127.0.0.53, which is the
// correct answer: that stub resolver is what the system actually queries. The upstream
// servers behind it are read from resolved's own runtime file when it is present, so
// diagnostics can distinguish "the stub is broken" from "upstream is broken".
func (p *Provider) DNSServers() ([]netip.AddrPort, error) {
	servers, err := parseResolvConf(resolvConf)
	if err != nil {
		return nil, err
	}
	// systemd-resolved publishes the real upstreams here.
	if len(servers) == 1 && servers[0].Addr().String() == "127.0.0.53" {
		if upstream, err := parseResolvConf("/run/systemd/resolve/resolv.conf"); err == nil && len(upstream) > 0 {
			servers = append(servers, upstream...)
		}
	}
	if len(servers) == 0 {
		return nil, types.ErrNotFound
	}
	return servers, nil
}

func parseResolvConf(path string) ([]netip.AddrPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netip.AddrPort
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := fields[1]
		// A scoped IPv6 address (fe80::1%eth0) is valid in resolv.conf.
		if i := strings.IndexByte(host, '%'); i > 0 {
			host = host[:i]
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		ap := netip.AddrPortFrom(addr, 53)
		if seen[ap.String()] {
			continue
		}
		seen[ap.String()] = true
		out = append(out, ap)
	}
	return out, sc.Err()
}
