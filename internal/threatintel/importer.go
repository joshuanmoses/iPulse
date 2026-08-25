package threatintel

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/version"
)

// Feed describes one configured source.
type Feed struct {
	Name string
	// URL and Path are mutually exclusive.
	URL  string
	Path string
	// Format selects the parser; empty means sniff.
	Format Format
	// Kind restricts the accepted indicator kinds.
	Kind Kind
	// Confidence is applied to every indicator from this feed.
	Confidence string
	// Column and Field configure the CSV and JSON parsers.
	Column int
	Field  string
	// ETag from the previous import, so an unchanged feed is not re-parsed.
	ETag string
}

// ImportResult reports the outcome of one feed import.
type ImportResult struct {
	Feed       string
	Format     Format
	Indicators []Indicator
	Skipped    int
	Truncated  bool
	// NotModified reports that the server said the feed is unchanged.
	NotModified bool
	ETag        string
	Bytes       int64
	Duration    time.Duration
}

// Importer fetches and parses feeds.
type Importer struct {
	client *http.Client
	// maxBytes bounds a single feed.
	maxBytes int64
	// maxIndicators bounds a single import.
	maxIndicators int
}

// NewImporter creates an importer.
func NewImporter(timeout time.Duration, maxBytes int64, maxIndicators int) *Importer {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	if maxIndicators <= 0 {
		maxIndicators = 2_000_000
	}
	return &Importer{
		client:        &http.Client{Timeout: timeout},
		maxBytes:      maxBytes,
		maxIndicators: maxIndicators,
	}
}

// Import fetches and parses one feed.
func (i *Importer) Import(ctx context.Context, feed Feed) (ImportResult, error) {
	start := time.Now()
	res := ImportResult{Feed: feed.Name}

	var (
		body    io.ReadCloser
		bytes   int64
		etag    string
		gzipped bool
		err     error
	)
	switch {
	case feed.Path != "":
		body, bytes, gzipped, err = i.openFile(feed.Path)
	case feed.URL != "":
		var notModified bool
		body, bytes, etag, gzipped, notModified, err = i.fetch(ctx, feed)
		if notModified {
			res.NotModified = true
			res.ETag = feed.ETag
			res.Duration = time.Since(start)
			return res, nil
		}
	default:
		return res, fmt.Errorf("threatintel: feed %q has neither a url nor a path", feed.Name)
	}
	if err != nil {
		return res, err
	}
	defer body.Close()

	reader := io.Reader(io.LimitReader(body, i.maxBytes))
	if gzipped {
		zr, err := gzip.NewReader(reader)
		if err != nil {
			return res, fmt.Errorf("threatintel: feed %q is not valid gzip: %w", feed.Name, err)
		}
		defer zr.Close()
		reader = io.LimitReader(zr, i.maxBytes)
	}

	var restrict []Kind
	switch feed.Kind {
	case KindIP:
		// An IP feed may legitimately contain single addresses and prefixes.
		restrict = []Kind{KindIP, KindCIDR}
	case KindCIDR:
		restrict = []Kind{KindCIDR, KindIP}
	case KindDomain:
		restrict = []Kind{KindDomain}
	}

	parsed, err := Parse(reader, ParseOptions{
		Format: feed.Format, Column: feed.Column, Field: feed.Field,
		Restrict: restrict, MaxIndicators: i.maxIndicators,
	})
	if err != nil {
		return res, fmt.Errorf("threatintel: parse feed %q: %w", feed.Name, err)
	}

	res.Indicators = parsed.Indicators
	res.Skipped = parsed.Skipped
	res.Truncated = parsed.Truncated
	res.Format = parsed.Format
	res.ETag = etag
	res.Bytes = bytes
	res.Duration = time.Since(start)

	if len(res.Indicators) == 0 {
		// A feed that parses to nothing is a configuration problem, not a success.
		return res, fmt.Errorf("threatintel: feed %q yielded no indicators (%d lines unusable); check its format",
			feed.Name, parsed.Skipped)
	}
	return res, nil
}

func (i *Importer) openFile(path string) (io.ReadCloser, int64, bool, error) {
	// A file: URL is accepted for symmetry with the URL form.
	if strings.HasPrefix(path, "file://") {
		if u, err := url.Parse(path); err == nil {
			path = u.Path
		}
	}
	clean := filepath.Clean(path)
	f, err := os.Open(clean)
	if err != nil {
		return nil, 0, false, fmt.Errorf("threatintel: open %s: %w", clean, err)
	}
	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	return f, size, strings.HasSuffix(strings.ToLower(clean), ".gz"), nil
}

func (i *Importer) fetch(ctx context.Context, feed Feed) (io.ReadCloser, int64, string, bool, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, 0, "", false, false, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "text/plain, application/json, */*")
	// Conditional request: an unchanged feed costs one round trip instead of a download.
	if feed.ETag != "" {
		req.Header.Set("If-None-Match", feed.ETag)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, 0, "", false, false, fmt.Errorf("threatintel: fetch %s: %w", feed.Name, err)
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return nil, 0, feed.ETag, false, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, "", false, false,
			fmt.Errorf("threatintel: feed %s returned status %d", feed.Name, resp.StatusCode)
	}

	gzipped := strings.HasSuffix(strings.ToLower(feed.URL), ".gz") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "gzip")
	// The transport transparently decodes Content-Encoding: gzip, so only an explicitly
	// gzipped body needs decoding here.
	if resp.Uncompressed {
		gzipped = false
	}
	return resp.Body, resp.ContentLength, resp.Header.Get("ETag"), gzipped, false, nil
}

// ConfidenceOf normalises a configured confidence value.
func ConfidenceOf(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return "low"
	case "high":
		return "high"
	case "medium", "":
		return "medium"
	default:
		return "medium"
	}
}
