// Package security holds cross-cutting defensive helpers: log-value sanitisation,
// file-permission enforcement and privilege reporting.
package security

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLogValueLen bounds a single sanitised log value. Anything longer is truncated
// with an explicit marker so a hostile value cannot flood the log.
const MaxLogValueLen = 512

// SanitizeValue makes an untrusted string safe to place in a structured log record.
//
// Untrusted strings reach iPulse from process names, executable paths, SSIDs, reverse
// DNS answers, threat-feed comments and HTTP responses. Without sanitising them a
// hostile value containing a newline plus "IPULSE-1001 ..." could forge a log record,
// and control characters could corrupt a terminal. This escapes control characters and
// newlines, replaces invalid UTF-8, and truncates.
//
// It deliberately does not add surrounding quotes: quoting is a property of the
// human-readable text format, applied at render time by NeedsQuoting, so the value
// stored in the database and emitted as JSON is the value itself.
func SanitizeValue(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > MaxLogValueLen*4 {
		s = s[:MaxLogValueLen*4]
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	written := 0
	for _, r := range s {
		if written >= MaxLogValueLen {
			b.WriteString("...[truncated]")
			break
		}
		switch {
		case r == utf8.RuneError:
			b.WriteString("\\ufffd")
			written += 6
		case r == '\n':
			b.WriteString("\\n")
			written += 2
		case r == '\r':
			b.WriteString("\\r")
			written += 2
		case r == '\t':
			b.WriteString("\\t")
			written += 2
		case r == '"':
			b.WriteString("\\\"")
			written += 2
		case r == '\\':
			b.WriteString("\\\\")
			written += 2
		case r == ' ' || r == '=':
			b.WriteRune(r)
			written++
		case r < 0x20 || r == 0x7f:
			b.WriteString("\\x" + zeroPad(strconv.FormatInt(int64(r), 16)))
			written += 4
		case !unicode.IsPrint(r):
			b.WriteString("\\u" + zeroPad4(strconv.FormatInt(int64(r), 16)))
			written += 6
		default:
			b.WriteRune(r)
			written++
		}
	}
	return b.String()
}

// NeedsQuoting reports whether a sanitised value must be quoted when rendered in the
// Key=Value text format, so a value containing a space or an equals sign cannot be
// mis-parsed.
func NeedsQuoting(s string) bool {
	if s == "" {
		return false
	}
	return strings.ContainsAny(s, " =\"")
}

// SanitizeKey restricts a field key to the identifier charset used by the log format.
func SanitizeKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9' && i > 0:
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "Field"
	}
	return b.String()
}

// SanitizeSingleLine strips newlines and control characters without quoting. Use for
// free-text message summaries where Key=Value parsing does not apply.
func SanitizeSingleLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n >= MaxLogValueLen {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}

func zeroPad(s string) string {
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

func zeroPad4(s string) string {
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
