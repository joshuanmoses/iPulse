// Package threatintel imports locally-held threat intelligence and matches observed
// connections against it.
//
// Two principles shape this package. First, no vendor is assumed: feeds are described by
// format, not by provider, and the common shapes (plain lists, hosts files, CSV exports,
// JSON documents) are all handled. Second, a match is evidence, not a verdict: iPulse
// reports the indicator, its source and its confidence, and never blocks traffic or
// describes a match as confirmed malicious activity.
package threatintel

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Format identifies a feed's on-disk shape.
type Format string

// Feed formats.
const (
	// FormatPlain is one indicator per line, with # or ; comments.
	FormatPlain Format = "plain"
	// FormatHosts is a hosts file: an address followed by one or more names.
	FormatHosts Format = "hosts"
	// FormatCSV is comma-separated values with the indicator in a chosen column.
	FormatCSV Format = "csv"
	// FormatJSON is a JSON array or object containing indicators.
	FormatJSON Format = "json"
	// FormatAuto sniffs the content.
	FormatAuto Format = "auto"
)

// Kind identifies what an indicator describes.
type Kind string

// Indicator kinds.
const (
	KindIP     Kind = "ip"
	KindCIDR   Kind = "cidr"
	KindDomain Kind = "domain"
)

// Indicator is one imported indicator of compromise.
type Indicator struct {
	Value string
	Kind  Kind
	// Note carries any trailing comment from the feed, which often explains why the
	// indicator is listed.
	Note string
}

// ParseOptions configures parsing.
type ParseOptions struct {
	Format Format
	// Column is the 1-based CSV column holding the indicator.
	Column int
	// Field is the JSON field holding the indicator, as a dot path.
	Field string
	// Restrict limits the accepted kinds; empty accepts all.
	Restrict []Kind
	// MaxIndicators bounds a single import.
	MaxIndicators int
}

// ParseResult reports what an import produced.
type ParseResult struct {
	Indicators []Indicator
	// Skipped counts lines that were not usable, which is worth reporting: a feed that
	// silently yields nothing is indistinguishable from a working one otherwise.
	Skipped int
	// Truncated reports that the indicator limit was reached.
	Truncated bool
	Format    Format
}

// maxLineLength bounds a single line, so a malformed feed cannot exhaust memory.
const maxLineLength = 64 << 10

// Parse reads indicators from a feed.
func Parse(r io.Reader, opts ParseOptions) (ParseResult, error) {
	if opts.MaxIndicators <= 0 {
		opts.MaxIndicators = 2_000_000
	}
	format := opts.Format
	if format == "" {
		format = FormatAuto
	}

	// Sniffing needs a peek at the start of the stream.
	br := bufio.NewReaderSize(r, 64<<10)
	if format == FormatAuto {
		head, err := br.Peek(4096)
		if err != nil && len(head) == 0 {
			return ParseResult{}, fmt.Errorf("threatintel: empty feed")
		}
		format = Sniff(head)
	}

	switch format {
	case FormatJSON:
		return parseJSON(br, opts, format)
	case FormatCSV:
		return parseCSV(br, opts, format)
	case FormatHosts:
		return parseLines(br, opts, format, true)
	default:
		return parseLines(br, opts, format, false)
	}
}

// Sniff guesses a feed's format from its opening bytes.
func Sniff(head []byte) Format {
	trimmed := strings.TrimSpace(string(head))
	if trimmed == "" {
		return FormatPlain
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		return FormatJSON
	}

	// Examine the first few non-comment lines.
	lines := strings.Split(trimmed, "\n")
	commas, hostsLike, checked := 0, 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		checked++
		if strings.Count(line, ",") >= 1 {
			commas++
		}
		fields := strings.Fields(line)
		// A hosts file starts each line with an address followed by a name.
		if len(fields) >= 2 {
			if _, err := netip.ParseAddr(fields[0]); err == nil {
				hostsLike++
			}
		}
		if checked >= 8 {
			break
		}
	}
	switch {
	case checked == 0:
		return FormatPlain
	case hostsLike*2 >= checked:
		return FormatHosts
	case commas*2 >= checked:
		return FormatCSV
	default:
		return FormatPlain
	}
}

// parseLines handles the plain and hosts formats.
func parseLines(r io.Reader, opts ParseOptions, format Format, hosts bool) (ParseResult, error) {
	res := ParseResult{Format: format}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineLength)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") ||
			strings.HasPrefix(line, "//") {
			continue
		}
		// A trailing comment usually explains the entry, which is worth keeping.
		value, note := splitComment(line)
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}

		if hosts {
			// An address followed by names: the names are the indicators, and the
			// address is the sinkhole the feed redirects them to.
			if _, err := netip.ParseAddr(fields[0]); err == nil && len(fields) >= 2 {
				for _, name := range fields[1:] {
					if ind, ok := classify(name, opts.Restrict); ok {
						ind.Note = note
						res.Indicators = append(res.Indicators, ind)
						if len(res.Indicators) >= opts.MaxIndicators {
							res.Truncated = true
							return res, nil
						}
					} else {
						res.Skipped++
					}
				}
				continue
			}
		}

		if ind, ok := classify(fields[0], opts.Restrict); ok {
			ind.Note = note
			res.Indicators = append(res.Indicators, ind)
			if len(res.Indicators) >= opts.MaxIndicators {
				res.Truncated = true
				return res, nil
			}
		} else {
			res.Skipped++
		}
	}
	return res, sc.Err()
}

func parseCSV(r io.Reader, opts ParseOptions, format Format) (ParseResult, error) {
	res := ParseResult{Format: format}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // feeds are not always rectangular
	cr.LazyQuotes = true
	cr.Comment = '#'

	column := opts.Column
	if column <= 0 {
		column = 1
	}
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A single malformed row must not abandon the whole feed.
			res.Skipped++
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			return res, err
		}
		if len(record) < column {
			res.Skipped++
			continue
		}
		value := strings.TrimSpace(record[column-1])
		ind, ok := classify(value, opts.Restrict)
		if !ok {
			// The first row is usually a header, which is expected to fail.
			res.Skipped++
			continue
		}
		if len(record) > column {
			ind.Note = strings.TrimSpace(record[len(record)-1])
		}
		res.Indicators = append(res.Indicators, ind)
		if len(res.Indicators) >= opts.MaxIndicators {
			res.Truncated = true
			return res, nil
		}
	}
	return res, nil
}

// parseJSON handles arrays of strings, arrays of objects and objects wrapping either.
func parseJSON(r io.Reader, opts ParseOptions, format Format) (ParseResult, error) {
	res := ParseResult{Format: format}
	// Feeds are bounded so a hostile or broken endpoint cannot exhaust memory.
	data, err := io.ReadAll(io.LimitReader(r, 256<<20))
	if err != nil {
		return res, err
	}

	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return res, fmt.Errorf("threatintel: invalid JSON feed: %w", err)
	}
	fieldPath := strings.Split(opts.Field, ".")
	if opts.Field == "" {
		fieldPath = nil
	}

	var walk func(node any)
	walk = func(node any) {
		if len(res.Indicators) >= opts.MaxIndicators {
			res.Truncated = true
			return
		}
		switch v := node.(type) {
		case []any:
			for _, item := range v {
				walk(item)
			}
		case map[string]any:
			// An explicit field path wins when it resolves.
			if len(fieldPath) > 0 {
				if val, ok := resolvePath(v, fieldPath); ok {
					if s, ok := val.(string); ok {
						if ind, ok := classify(s, opts.Restrict); ok {
							res.Indicators = append(res.Indicators, ind)
							return
						}
					}
				}
			}
			// Otherwise look at the keys feeds commonly use, then recurse.
			for _, key := range []string{"indicator", "ip", "ip_address", "address", "domain",
				"host", "hostname", "value", "cidr", "network"} {
				if val, ok := v[key]; ok {
					if s, ok := val.(string); ok {
						if ind, ok := classify(s, opts.Restrict); ok {
							if note, ok := v["note"].(string); ok {
								ind.Note = note
							} else if note, ok := v["description"].(string); ok {
								ind.Note = note
							}
							res.Indicators = append(res.Indicators, ind)
							return
						}
					}
				}
			}
			for _, val := range v {
				switch val.(type) {
				case []any, map[string]any:
					walk(val)
				}
			}
		case string:
			if ind, ok := classify(v, opts.Restrict); ok {
				res.Indicators = append(res.Indicators, ind)
			} else {
				res.Skipped++
			}
		}
	}
	walk(doc)
	return res, nil
}

func resolvePath(node map[string]any, path []string) (any, bool) {
	var current any = node
	for _, part := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// classify decides what an indicator string describes, rejecting anything that is
// neither an address, a prefix nor a plausible domain.
func classify(value string, restrict []Kind) (Indicator, bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return Indicator{}, false
	}
	// Some feeds write a URL; the host part is the indicator.
	if i := strings.Index(value, "://"); i >= 0 {
		value = value[i+3:]
		if j := strings.IndexAny(value, "/?#"); j >= 0 {
			value = value[:j]
		}
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return Indicator{}, false
	}

	if p, err := netip.ParsePrefix(value); err == nil {
		if !allowed(KindCIDR, restrict) {
			return Indicator{}, false
		}
		return Indicator{Value: p.Masked().String(), Kind: KindCIDR}, true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if !allowed(KindIP, restrict) {
			return Indicator{}, false
		}
		return Indicator{Value: addr.Unmap().String(), Kind: KindIP}, true
	}
	if isPlausibleDomain(value) {
		if !allowed(KindDomain, restrict) {
			return Indicator{}, false
		}
		return Indicator{Value: strings.ToLower(value), Kind: KindDomain}, true
	}
	return Indicator{}, false
}

func allowed(k Kind, restrict []Kind) bool {
	if len(restrict) == 0 {
		return true
	}
	for _, r := range restrict {
		if r == k {
			return true
		}
	}
	return false
}

// isPlausibleDomain rejects the header rows, prose and IDs that appear in real feeds.
func isPlausibleDomain(s string) bool {
	if len(s) < 4 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	if strings.ContainsAny(s, " \t/\\@:;,()[]{}\"'") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		c := tld[i]
		// A numeric or symbolic final label is not a domain.
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			return false
		}
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// splitComment separates a trailing comment from a line.
func splitComment(line string) (value, note string) {
	for _, marker := range []string{" #", "\t#", " ;", "\t;", " //"} {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(strings.TrimLeft(line[i:], " \t#;/"))
		}
	}
	return line, ""
}
