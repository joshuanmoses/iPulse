package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePlainList(t *testing.T) {
	feed := `# Example blocklist
# Generated 2026-08-24
203.0.113.20
198.51.100.0/24
bad.example
evil.example.org   # known phishing host

; another comment style
2001:db8::1
2001:db8:1::/48
`
	res, err := Parse(strings.NewReader(feed), ParseOptions{Format: FormatPlain})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 6 {
		t.Fatalf("parsed %d indicators, want 6: %+v", len(res.Indicators), res.Indicators)
	}
	byValue := map[string]Indicator{}
	for _, ind := range res.Indicators {
		byValue[ind.Value] = ind
	}
	if byValue["203.0.113.20"].Kind != KindIP {
		t.Errorf("address classified as %q", byValue["203.0.113.20"].Kind)
	}
	if byValue["198.51.100.0/24"].Kind != KindCIDR {
		t.Errorf("prefix classified as %q", byValue["198.51.100.0/24"].Kind)
	}
	if byValue["bad.example"].Kind != KindDomain {
		t.Errorf("domain classified as %q", byValue["bad.example"].Kind)
	}
	// A trailing comment usually explains the entry, so it is kept.
	if byValue["evil.example.org"].Note != "known phishing host" {
		t.Errorf("note = %q", byValue["evil.example.org"].Note)
	}
}

func TestParseHostsFile(t *testing.T) {
	feed := `# hosts-format blocklist
0.0.0.0 ads.example
0.0.0.0 tracker.example analytics.example
127.0.0.1 localhost
::1 ip6-localhost
`
	res, err := Parse(strings.NewReader(feed), ParseOptions{Format: FormatHosts})
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]bool{}
	for _, ind := range res.Indicators {
		values[ind.Value] = true
		if ind.Kind != KindDomain {
			t.Errorf("%s classified as %q, want domain", ind.Value, ind.Kind)
		}
	}
	for _, want := range []string{"ads.example", "tracker.example", "analytics.example"} {
		if !values[want] {
			t.Errorf("missing %s from %v", want, values)
		}
	}
	// "localhost" has no dot and is not a usable indicator.
	if values["localhost"] {
		t.Error("localhost should not be imported as an indicator")
	}
}

func TestParseCSV(t *testing.T) {
	feed := `ip,first_seen,category
203.0.113.20,2026-08-01,c2
198.51.100.7,2026-08-02,phishing
not-an-indicator,2026-08-03,junk
`
	res, err := Parse(strings.NewReader(feed), ParseOptions{Format: FormatCSV, Column: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 2 {
		t.Fatalf("parsed %d indicators, want 2: %+v", len(res.Indicators), res.Indicators)
	}
	// The header row and the junk row are skipped, and that is reported.
	if res.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", res.Skipped)
	}
	if res.Indicators[0].Note != "c2" {
		t.Errorf("note = %q, want the category column", res.Indicators[0].Note)
	}

	// A different column can be selected.
	feed2 := "category,indicator\nc2,203.0.113.20\n"
	res2, err := Parse(strings.NewReader(feed2), ParseOptions{Format: FormatCSV, Column: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Indicators) != 1 || res2.Indicators[0].Value != "203.0.113.20" {
		t.Errorf("column selection failed: %+v", res2.Indicators)
	}
}

func TestParseJSONShapes(t *testing.T) {
	cases := []string{
		`["203.0.113.20","bad.example"]`,
		`[{"indicator":"203.0.113.20"},{"indicator":"bad.example"}]`,
		`{"data":[{"ip":"203.0.113.20"},{"domain":"bad.example"}]}`,
	}
	for _, body := range cases {
		res, err := Parse(strings.NewReader(body), ParseOptions{Format: FormatJSON})
		if err != nil {
			t.Errorf("Parse(%s): %v", body, err)
			continue
		}
		if len(res.Indicators) != 2 {
			t.Errorf("Parse(%s) produced %d indicators: %+v", body, len(res.Indicators), res.Indicators)
		}
	}

	// An explicit field path.
	res, err := Parse(strings.NewReader(`[{"attributes":{"value":"203.0.113.20"}}]`),
		ParseOptions{Format: FormatJSON, Field: "attributes.value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 1 || res.Indicators[0].Value != "203.0.113.20" {
		t.Errorf("field path parse failed: %+v", res.Indicators)
	}
}

func TestSniffFormats(t *testing.T) {
	cases := map[string]Format{
		"203.0.113.20\nbad.example\n":              FormatPlain,
		"0.0.0.0 ads.example\n0.0.0.0 x.example\n": FormatHosts,
		"ip,category\n203.0.113.20,c2\n":           FormatCSV,
		`[{"ip":"203.0.113.20"}]`:                  FormatJSON,
		`{"data":[]}`:                              FormatJSON,
		"":                                         FormatPlain,
	}
	for body, want := range cases {
		if got := Sniff([]byte(body)); got != want {
			t.Errorf("Sniff(%q) = %q, want %q", firstLine(body), got, want)
		}
	}
}

func TestAutoFormatSelection(t *testing.T) {
	res, err := Parse(strings.NewReader("0.0.0.0 ads.example\n0.0.0.0 tracker.example\n"),
		ParseOptions{Format: FormatAuto})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatHosts {
		t.Errorf("auto-detected %q, want hosts", res.Format)
	}
	if len(res.Indicators) != 2 {
		t.Errorf("parsed %+v", res.Indicators)
	}
}

// TestClassifyRejectsJunk matters because a feed with a header row or prose must not
// import garbage as indicators.
func TestClassifyRejectsJunk(t *testing.T) {
	junk := []string{
		"ip", "indicator", "# comment", "Updated daily", "1234", "192.168", "a.b",
		"has space.example", "http://", "-", "", "example..com",
	}
	for _, s := range junk {
		if ind, ok := classify(s, nil); ok {
			t.Errorf("classify(%q) accepted it as %s %q", s, ind.Kind, ind.Value)
		}
	}
}

func TestClassifyExtractsHostFromURL(t *testing.T) {
	ind, ok := classify("https://bad.example/path?q=1", nil)
	if !ok || ind.Value != "bad.example" || ind.Kind != KindDomain {
		t.Errorf("URL handling: %+v ok=%v", ind, ok)
	}
}

func TestKindRestriction(t *testing.T) {
	feed := "203.0.113.20\nbad.example\n198.51.100.0/24\n"
	res, err := Parse(strings.NewReader(feed), ParseOptions{
		Format: FormatPlain, Restrict: []Kind{KindDomain},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 1 || res.Indicators[0].Kind != KindDomain {
		t.Errorf("restriction failed: %+v", res.Indicators)
	}
	if res.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", res.Skipped)
	}
}

func TestIndicatorLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("203.0.113.")
		b.WriteString(string(rune('0' + i%10)))
		b.WriteByte('\n')
	}
	res, err := Parse(strings.NewReader(b.String()), ParseOptions{Format: FormatPlain, MaxIndicators: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 10 || !res.Truncated {
		t.Errorf("limit not enforced: %d indicators, truncated=%v", len(res.Indicators), res.Truncated)
	}
}

func TestImportFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("203.0.113.20\nbad.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imp := NewImporter(10*time.Second, 1<<20, 1000)
	res, err := imp.Import(context.Background(), Feed{Name: "local", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 2 {
		t.Errorf("imported %+v", res.Indicators)
	}
	if res.Duration <= 0 {
		t.Error("expected a duration")
	}
}

func TestImportFromURLWithETag(t *testing.T) {
	const etag = `"abc123"`
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte("203.0.113.20\n198.51.100.7\n"))
	}))
	defer srv.Close()

	imp := NewImporter(10*time.Second, 1<<20, 1000)
	res, err := imp.Import(context.Background(), Feed{Name: "remote", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 2 || res.ETag != etag {
		t.Errorf("first import: %d indicators, etag=%q", len(res.Indicators), res.ETag)
	}

	// The conditional request avoids re-downloading an unchanged feed.
	res2, err := imp.Import(context.Background(), Feed{Name: "remote", URL: srv.URL, ETag: etag})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.NotModified {
		t.Error("expected the feed to be reported as unchanged")
	}
	if len(res2.Indicators) != 0 {
		t.Errorf("an unchanged feed should parse nothing, got %d", len(res2.Indicators))
	}
}

// TestImportEmptyFeedIsAnError is deliberate: a feed that parses to nothing is a
// configuration problem, and reporting success would hide it.
func TestImportEmptyFeedIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# only comments\n# nothing else\n"))
	}))
	defer srv.Close()

	imp := NewImporter(10*time.Second, 1<<20, 1000)
	if _, err := imp.Import(context.Background(), Feed{Name: "empty", URL: srv.URL}); err == nil {
		t.Error("expected an error for a feed with no indicators")
	}
}

func TestImportRejectsBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	imp := NewImporter(10*time.Second, 1<<20, 1000)
	if _, err := imp.Import(context.Background(), Feed{Name: "denied", URL: srv.URL}); err == nil {
		t.Error("expected an error for a 403 response")
	}
}

func TestImportRequiresASource(t *testing.T) {
	imp := NewImporter(time.Second, 1<<20, 100)
	if _, err := imp.Import(context.Background(), Feed{Name: "empty"}); err == nil {
		t.Error("expected an error when neither url nor path is set")
	}
}

// stubLookup is an in-memory Lookup for matcher tests.
type stubLookup struct {
	ips     map[string][]Match
	domains map[string][]Match
	calls   int
}

func (s *stubLookup) MatchIP(_ context.Context, addr netip.Addr) ([]Match, error) {
	s.calls++
	return s.ips[addr.String()], nil
}

func (s *stubLookup) MatchDomain(_ context.Context, domain string) ([]Match, error) {
	s.calls++
	return s.domains[domain], nil
}

func TestMatcherFindsAndCaches(t *testing.T) {
	lookup := &stubLookup{ips: map[string][]Match{
		"203.0.113.20": {{Indicator: "203.0.113.20", Kind: KindIP, Source: "feed", Confidence: "high"}},
	}}
	m := NewMatcher(MatcherConfig{}, lookup)
	ctx := context.Background()
	addr := netip.MustParseAddr("203.0.113.20")

	matches, err := m.MatchAddr(ctx, addr)
	if err != nil || len(matches) != 1 {
		t.Fatalf("first match: %+v err=%v", matches, err)
	}
	// Connection tables repeat the same destinations every cycle, so the second lookup
	// must come from the cache.
	if _, err := m.MatchAddr(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if lookup.calls != 1 {
		t.Errorf("store queried %d times, want 1", lookup.calls)
	}
	if s := m.Stats(); s.Hits != 1 || s.Cached != 1 {
		t.Errorf("stats = %+v", s)
	}

	// Invalidation forces a re-query, which is needed after an import.
	m.Invalidate()
	if _, err := m.MatchAddr(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if lookup.calls != 2 {
		t.Errorf("store queried %d times after invalidation, want 2", lookup.calls)
	}
}

// TestMatcherSkipsPrivateAddresses stops a feed entry for an RFC 1918 address from
// matching half the local network.
func TestMatcherSkipsPrivateAddresses(t *testing.T) {
	lookup := &stubLookup{ips: map[string][]Match{
		"192.168.1.50": {{Indicator: "192.168.1.50", Kind: KindIP, Source: "feed"}},
	}}
	m := NewMatcher(MatcherConfig{}, lookup)
	matches, err := m.MatchAddr(context.Background(), netip.MustParseAddr("192.168.1.50"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("private address matched: %+v", matches)
	}
	if lookup.calls != 0 {
		t.Error("a private address should not even be looked up")
	}

	// Unless explicitly enabled.
	m2 := NewMatcher(MatcherConfig{MatchPrivate: true}, lookup)
	if matches, _ := m2.MatchAddr(context.Background(), netip.MustParseAddr("192.168.1.50")); len(matches) != 1 {
		t.Errorf("with MatchPrivate the address should match: %+v", matches)
	}
}

func TestMatcherAllowList(t *testing.T) {
	lookup := &stubLookup{
		ips: map[string][]Match{
			"203.0.113.20": {{Indicator: "203.0.113.20", Source: "feed"}},
		},
		domains: map[string][]Match{
			"mirror.example": {{Indicator: "mirror.example", Source: "feed"}},
		},
	}
	m := NewMatcher(MatcherConfig{
		AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		AllowDomains:  []string{"example"},
	}, lookup)
	ctx := context.Background()

	if matches, _ := m.MatchAddr(ctx, netip.MustParseAddr("203.0.113.20")); len(matches) != 0 {
		t.Errorf("allow-listed address matched: %+v", matches)
	}
	if matches, _ := m.MatchDomain(ctx, "mirror.example"); len(matches) != 0 {
		t.Errorf("allow-listed domain matched: %+v", matches)
	}
	if s := m.Stats(); s.Allowed != 2 {
		t.Errorf("allow-listed count = %d, want 2", s.Allowed)
	}
}

func TestHighestConfidenceWins(t *testing.T) {
	matches := []Match{
		{Indicator: "a", Confidence: "low", Source: "feed-a"},
		{Indicator: "b", Confidence: "high", Source: "feed-b"},
		{Indicator: "c", Confidence: "medium", Source: "feed-c"},
	}
	best, ok := Highest(matches)
	if !ok || best.Source != "feed-b" {
		t.Errorf("Highest = %+v ok=%v", best, ok)
	}
	if _, ok := Highest(nil); ok {
		t.Error("no matches must report none")
	}
}

func TestConfidenceOf(t *testing.T) {
	cases := map[string]string{"low": "low", "LOW": "low", "high": "high", "": "medium", "bogus": "medium"}
	for in, want := range cases {
		if got := ConfidenceOf(in); got != want {
			t.Errorf("ConfidenceOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
