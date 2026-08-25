// Package publicip discovers the public addresses this host presents to the Internet,
// and enriches them with autonomous-system information.
//
// Discovery uses several independent providers and, by default, requires two of them to
// agree before a change is accepted: a single provider behind a CDN can briefly report
// someone else's address, and a spurious "your public IP changed" event undermines trust
// in every other event iPulse emits.
package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/version"
)

// Family identifies the address family being discovered.
type Family string

// Address families.
const (
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

// Result is one provider's answer.
type Result struct {
	Addr     netip.Addr    `json:"address"`
	Family   Family        `json:"family"`
	Provider string        `json:"provider"`
	Duration time.Duration `json:"duration"`
}

// Detector queries public-IP providers.
type Detector struct {
	client  *http.Client
	timeout time.Duration
}

// NewDetector builds a detector. The HTTP client is forced onto the requested address
// family so an IPv6 query cannot be silently answered over IPv4, which would report the
// wrong address entirely.
func NewDetector(timeout time.Duration) *Detector {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	return &Detector{timeout: timeout}
}

// Detect queries providers in order and returns every answer obtained, so the caller can
// require agreement. Providers are tried sequentially: this runs every few minutes and
// costs one small request, so there is no reason to fan out.
func (d *Detector) Detect(ctx context.Context, providers []string, family Family) ([]Result, error) {
	if len(providers) == 0 {
		return nil, errors.New("publicip: no providers configured")
	}
	client := d.clientFor(family)

	var (
		results []Result
		errs    []string
	)
	for _, p := range providers {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		addr, err := d.query(ctx, client, p, family)
		if err != nil {
			errs = append(errs, p+": "+shortError(err))
			continue
		}
		results = append(results, Result{
			Addr: addr, Family: family, Provider: p, Duration: time.Since(start),
		})
		// Two agreeing answers are enough to be confident; stop rather than querying
		// every provider on every cycle.
		if len(results) >= 2 && results[0].Addr == results[len(results)-1].Addr {
			break
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("publicip: no provider answered for %s: %s", family, strings.Join(errs, "; "))
	}
	return results, nil
}

// clientFor builds a client pinned to one address family.
func (d *Detector) clientFor(family Family) *http.Client {
	network := "tcp4"
	if family == IPv6 {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: d.timeout}
	return &http.Client{
		Timeout: d.timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: d.timeout,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
		},
	}
}

// query fetches one provider and extracts an address of the requested family.
func (d *Detector) query(ctx context.Context, client *http.Client, provider string, family Family) (netip.Addr, error) {
	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, provider, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	// A public-IP response is a few bytes; anything larger is not one.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := ParseResponse(string(body), family)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// ParseResponse extracts an address from a provider response.
//
// Three shapes are handled, which covers every provider in common use: a bare address, a
// key=value trace document (Cloudflare's /cdn-cgi/trace uses ip=), and JSON with an "ip"
// field. Anything else is rejected rather than guessed at.
func ParseResponse(body string, family Family) (netip.Addr, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return netip.Addr{}, errors.New("empty response")
	}

	// Bare address, the most common case.
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return validateFamily(addr, family)
	}

	// key=value lines.
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "ip") {
			if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
				return validateFamily(addr, family)
			}
		}
	}

	// A minimal JSON extraction, avoiding a full decode for a one-field document.
	if i := strings.Index(trimmed, `"ip"`); i >= 0 {
		rest := trimmed[i+4:]
		if j := strings.Index(rest, `"`); j >= 0 {
			rest = rest[j+1:]
			if k := strings.Index(rest, `"`); k > 0 {
				if addr, err := netip.ParseAddr(strings.TrimSpace(rest[:k])); err == nil {
					return validateFamily(addr, family)
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no address found in response %q", truncate(trimmed, 64))
}

func validateFamily(addr netip.Addr, family Family) (netip.Addr, error) {
	addr = addr.Unmap()
	switch family {
	case IPv4:
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("expected an IPv4 address, got %s", addr)
		}
	case IPv6:
		if addr.Is4() {
			return netip.Addr{}, fmt.Errorf("expected an IPv6 address, got %s", addr)
		}
	}
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("%s is not a global unicast address", addr)
	}
	return addr, nil
}

// Agree reports the address at least two providers reported, or the single answer when
// only one provider responded.
func Agree(results []Result) (netip.Addr, int, bool) {
	if len(results) == 0 {
		return netip.Addr{}, 0, false
	}
	counts := map[netip.Addr]int{}
	for _, r := range results {
		counts[r.Addr]++
	}
	var best netip.Addr
	bestCount := 0
	for addr, n := range counts {
		if n > bestCount || (n == bestCount && addr.Compare(best) < 0) {
			best, bestCount = addr, n
		}
	}
	return best, bestCount, true
}

// cgnatRange is the shared address space carriers use between the customer and the
// public Internet.
var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

// IsCGNAT reports whether an address is in carrier-grade NAT space.
func IsCGNAT(addr netip.Addr) bool { return cgnatRange.Contains(addr.Unmap()) }

func shortError(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg)-i < 40 {
		return msg[i+2:]
	}
	return truncate(msg, 80)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
