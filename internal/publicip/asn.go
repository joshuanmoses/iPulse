package publicip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/version"
)

// Network describes the autonomous system serving an address.
type Network struct {
	ASN     string `json:"asn,omitempty"`
	Org     string `json:"organization,omitempty"`
	Country string `json:"country,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	// Source names where the information came from, so an operator can tell whether an
	// external service was contacted.
	Source string `json:"source,omitempty"`
}

// Empty reports whether nothing was resolved.
func (n Network) Empty() bool { return n.ASN == "" && n.Org == "" && n.Country == "" }

// Describe renders the network for an event field.
func (n Network) Describe() string {
	parts := make([]string, 0, 3)
	if n.ASN != "" {
		parts = append(parts, n.ASN)
	}
	if n.Org != "" {
		parts = append(parts, n.Org)
	}
	if n.Country != "" {
		parts = append(parts, n.Country)
	}
	return strings.Join(parts, " ")
}

// Enricher resolves autonomous-system information for an address.
type Enricher struct {
	// httpTemplate is an optional HTTP endpoint with an {ip} placeholder. When empty,
	// the DNS-based lookup is used.
	httpTemplate string
	client       *http.Client
	resolver     *net.Resolver
	timeout      time.Duration
}

// NewEnricher builds an enricher. An empty template selects the DNS-based Team Cymru
// service, which needs no API key, no account and no HTTP request, and which iPulse
// therefore prefers: it is the least intrusive way to answer "who serves this address".
func NewEnricher(httpTemplate string, timeout time.Duration) *Enricher {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Enricher{
		httpTemplate: httpTemplate,
		client:       &http.Client{Timeout: timeout},
		resolver:     net.DefaultResolver,
		timeout:      timeout,
	}
}

// Lookup resolves the network for an address.
func (e *Enricher) Lookup(ctx context.Context, addr netip.Addr) (Network, error) {
	if !addr.IsValid() {
		return Network{}, fmt.Errorf("publicip: invalid address")
	}
	if e.httpTemplate != "" {
		return e.lookupHTTP(ctx, addr)
	}
	return e.lookupDNS(ctx, addr)
}

// lookupDNS queries the Team Cymru IP-to-ASN service over DNS TXT records.
//
// Two queries are needed: origin gives the ASN and prefix for the address, and the ASN
// record gives the organisation name. Both are plain DNS, so they work through the same
// resolver everything else uses and reveal only the address being looked up.
func (e *Enricher) lookupDNS(ctx context.Context, addr netip.Addr) (Network, error) {
	queryCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	name, err := cymruOriginName(addr)
	if err != nil {
		return Network{}, err
	}
	txts, err := e.resolver.LookupTXT(queryCtx, name)
	if err != nil {
		return Network{}, fmt.Errorf("publicip: asn lookup for %s: %w", addr, err)
	}
	if len(txts) == 0 {
		return Network{}, fmt.Errorf("publicip: no ASN record for %s", addr)
	}

	// Format: "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
	net1 := Network{Source: "cymru-dns"}
	fields := splitPipe(txts[0])
	if len(fields) > 0 && fields[0] != "" {
		// The origin record can list several ASNs for an anycast prefix.
		net1.ASN = "AS" + strings.Fields(fields[0])[0]
	}
	if len(fields) > 1 {
		net1.Prefix = fields[1]
	}
	if len(fields) > 2 {
		net1.Country = fields[2]
	}

	if net1.ASN != "" {
		// The organisation record is keyed by the AS-prefixed form: AS13335.asn.cymru.com.
		if txts, err := e.resolver.LookupTXT(queryCtx, net1.ASN+".asn.cymru.com"); err == nil && len(txts) > 0 {
			// Format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
			f := splitPipe(txts[0])
			if len(f) >= 5 {
				org := f[4]
				// The description ends with the registry country; drop it so the field
				// holds just the organisation name.
				if len(f) >= 2 {
					org = strings.TrimSuffix(org, ", "+f[1])
				}
				net1.Org = strings.TrimSpace(org)
			}
			if len(f) >= 2 && f[1] != "" {
				// The ASN record's country is the operator's registration, which is
				// more useful than the prefix's geolocation.
				net1.Country = f[1]
			}
		}
	}
	if net1.Empty() {
		return net1, fmt.Errorf("publicip: ASN record for %s could not be parsed", addr)
	}
	return net1, nil
}

// cymruOriginName builds the reverse-nibble query name for an address.
func cymruOriginName(addr netip.Addr) (string, error) {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0]), nil
	}
	if addr.Is6() {
		b := addr.As16()
		var sb strings.Builder
		// Nibbles in reverse order, as in ip6.arpa.
		for i := len(b) - 1; i >= 0; i-- {
			sb.WriteString(fmt.Sprintf("%x.%x.", b[i]&0x0f, b[i]>>4))
		}
		sb.WriteString("origin6.asn.cymru.com")
		return sb.String(), nil
	}
	return "", fmt.Errorf("publicip: unsupported address %s", addr)
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// lookupHTTP queries a configured HTTP enrichment endpoint. The response is decoded
// generically because every provider names its fields differently, and iPulse must not
// be tied to one of them.
func (e *Enricher) lookupHTTP(ctx context.Context, addr netip.Addr) (Network, error) {
	url := strings.ReplaceAll(e.httpTemplate, "{ip}", addr.String())
	reqCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return Network{}, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return Network{}, fmt.Errorf("publicip: enrichment request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Network{}, fmt.Errorf("publicip: enrichment returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Network{}, err
	}
	return ParseNetworkJSON(body)
}

// ParseNetworkJSON extracts ASN, organisation and country from an arbitrary JSON
// document, accepting the field names the common providers use.
func ParseNetworkJSON(body []byte) (Network, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Network{}, fmt.Errorf("publicip: enrichment response is not JSON: %w", err)
	}
	out := Network{Source: "http"}

	// Some providers nest the useful fields one level down.
	candidates := []map[string]any{doc}
	for _, key := range []string{"data", "asn", "network", "as", "org", "prefix"} {
		if nested, ok := doc[key].(map[string]any); ok {
			candidates = append(candidates, nested)
		}
	}
	for _, m := range candidates {
		for key, value := range m {
			str := stringify(value)
			if str == "" {
				continue
			}
			switch strings.ToLower(key) {
			case "asn", "as", "as_number", "autonomous_system_number", "asnumber":
				if out.ASN == "" {
					out.ASN = normaliseASN(str)
				}
			case "org", "organization", "organisation", "as_name", "asname", "isp",
				"as_org", "autonomous_system_organization", "descr":
				if out.Org == "" {
					out.Org = str
				}
			case "country", "country_code", "countrycode", "country_name":
				if out.Country == "" {
					out.Country = str
				}
			case "prefix", "network", "route", "cidr":
				if out.Prefix == "" && strings.Contains(str, "/") {
					out.Prefix = str
				}
			}
		}
	}
	if out.Empty() {
		return out, fmt.Errorf("publicip: enrichment response had no recognisable fields")
	}
	return out, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case json.Number:
		return t.String()
	}
	return ""
}

func normaliseASN(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(s), "AS") {
		return "AS" + strings.TrimPrefix(strings.ToUpper(s), "AS")
	}
	return "AS" + s
}

// ReverseDNS resolves the hostname for an address, returning an empty string when there
// is none. Reverse DNS is best-effort context, never a fact iPulse relies on.
func ReverseDNS(ctx context.Context, resolver *net.Resolver, addr netip.Addr, timeout time.Duration) string {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, addr.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
