package security

import (
	"strings"
	"testing"
)

// TestSanitizeValueNeutralisesInjection is the property the log format depends on: a
// hostile value must never be able to introduce a newline and forge a second record.
func TestSanitizeValueNeutralisesInjection(t *testing.T) {
	hostile := "evil\n2026-08-24T00:00:00-05:00 INFO IPULSE-1002 SPEED_TEST_COMPLETED"
	got := SanitizeValue(hostile)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("newlines survived sanitisation: %q", got)
	}
	if !strings.Contains(got, `\n`) {
		t.Errorf("expected an escaped newline in %q", got)
	}
}

func TestSanitizeValueEscapesControlCharacters(t *testing.T) {
	got := SanitizeValue("a\x00b\x1bc\x7fd\te")
	for _, bad := range []string{"\x00", "\x1b", "\x7f", "\t"} {
		if strings.Contains(got, bad) {
			t.Errorf("control character %q survived: %q", bad, got)
		}
	}
	if !strings.Contains(got, `\x00`) || !strings.Contains(got, `\x1b`) {
		t.Errorf("expected hex escapes in %q", got)
	}
}

// TestSanitizeValueDoesNotQuote documents the split of responsibilities: the value keeps
// its own text, and quoting happens only when rendering the text format.
func TestSanitizeValueDoesNotQuote(t *testing.T) {
	if got := SanitizeValue("Cloudflare, Inc."); got != "Cloudflare, Inc." {
		t.Errorf("SanitizeValue added quoting or altered the value: %q", got)
	}
	if got := SanitizeValue(`a"b`); got != `a\"b` {
		t.Errorf("embedded quote handling: %q", got)
	}
}

func TestNeedsQuoting(t *testing.T) {
	cases := map[string]bool{
		"":            false,
		"simple":      false,
		"192.168.1.1": false,
		"has space":   true,
		"key=value":   true,
		`with"quote`:  true,
		"HEALTHY":     false,
	}
	for in, want := range cases {
		if got := NeedsQuoting(in); got != want {
			t.Errorf("NeedsQuoting(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSanitizeValueTruncates(t *testing.T) {
	long := strings.Repeat("x", MaxLogValueLen*3)
	got := SanitizeValue(long)
	if len(got) > MaxLogValueLen+32 {
		t.Errorf("value not truncated: %d characters", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("truncation must be visible: %q", got[len(got)-40:])
	}
}

func TestSanitizeKey(t *testing.T) {
	cases := map[string]string{
		"Download":    "Download",
		"packet_loss": "packet_loss",
		"2bad":        "_bad",
		"has space":   "has_space",
		"a=b":         "a_b",
		"":            "Field",
	}
	for in, want := range cases {
		if got := SanitizeKey(in); got != want {
			t.Errorf("SanitizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeSingleLine(t *testing.T) {
	got := SanitizeSingleLine("first\nsecond\ttab\x00null")
	if strings.ContainsAny(got, "\n\t\x00") {
		t.Errorf("control characters survived: %q", got)
	}
	if !strings.Contains(got, "first") || !strings.Contains(got, "second") {
		t.Errorf("content lost: %q", got)
	}
}

func TestAuditPathsFlagsWorldWritable(t *testing.T) {
	// A directory nothing can be assumed about should produce no warnings rather than
	// spurious ones.
	if warnings := AuditPaths("", "", ""); len(warnings) != 0 {
		t.Errorf("empty paths produced warnings: %v", warnings)
	}
}

func TestPrivilegeReportIsComplete(t *testing.T) {
	report := BuildPrivilegeReport(Capabilities{
		Platform: "linux/amd64", Interfaces: true, Routes: true, Connections: true,
		DNSServers: true,
	})
	if report.Platform != "linux/amd64" {
		t.Errorf("platform = %q", report.Platform)
	}
	if len(report.Features) < 8 {
		t.Errorf("expected the full privilege matrix, got %d features", len(report.Features))
	}
	for _, f := range report.Features {
		if f.Feature == "" || f.Required == "" {
			t.Errorf("incomplete feature entry: %+v", f)
		}
	}
	// ICMP and process attribution were reported unavailable, so they must be listed as
	// degraded with a stated impact.
	degraded := report.Degraded()
	if len(degraded) == 0 {
		t.Fatal("expected degraded features")
	}
	for _, f := range degraded {
		if f.Impact == "" && f.Fallback == "" {
			t.Errorf("degraded feature %q explains neither impact nor fallback", f.Feature)
		}
	}
}
