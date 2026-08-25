package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCatalogIntegrity(t *testing.T) {
	names := map[string]int{}
	for _, d := range All() {
		if d.Name == "" || d.Summary == "" || d.Trigger == "" || d.Action == "" {
			t.Errorf("IPULSE-%d: incomplete catalog entry %+v", d.Code, d)
		}
		if d.Name != strings.ToUpper(d.Name) {
			t.Errorf("IPULSE-%d: name %q must be upper case", d.Code, d.Name)
		}
		if prev, dup := names[d.Name]; dup {
			t.Errorf("duplicate event name %q on %d and %d", d.Name, prev, d.Code)
		}
		names[d.Name] = d.Code
		if got := CategoryForCode(d.Code); got != d.Category {
			t.Errorf("IPULSE-%d: category %s does not match range category %s", d.Code, d.Category, got)
		}
		if len(d.Fields) == 0 {
			t.Errorf("IPULSE-%d: no documented fields", d.Code)
		}
	}
	if len(All()) < 90 {
		t.Errorf("catalog unexpectedly small: %d events", len(All()))
	}
}

func TestCatalogCoversUsedCodes(t *testing.T) {
	for _, code := range []int{SpeedTestCompleted, InternetConnectivityLost, ThreatIntelligenceMatch,
		LatencyDegradation, PublicIPChanged, AgentStarted, PanicRecovered} {
		if _, ok := Lookup(code); !ok {
			t.Errorf("code %d missing from catalog", code)
		}
	}
}

// TestTextFormatMatchesDocumentedExample locks the log format against the example in
// the requirements, since operators and log parsers depend on it.
func TestTextFormatMatchesDocumentedExample(t *testing.T) {
	loc := time.FixedZone("CDT", -5*3600)
	ts := time.Date(2026, 8, 24, 14, 32, 10, 0, loc)
	ev := New(SpeedTestCompleted).WithTime(ts).WithFields(
		Fields{}.
			AddUnit("Download", 487.24, "Mbps").
			AddUnit("Upload", 41.83, "Mbps").
			AddUnit("Latency", 18.61, "ms").
			AddUnit("Jitter", 2.94, "ms").
			AddPercent("PacketLoss", 0).
			Add("Status", "HEALTHY").
			Add("TestServer", "example").
			AddDuration("Duration", 12400*time.Millisecond),
	)
	want := strings.Join([]string{
		"2026-08-24T14:32:10-05:00 INFO IPULSE-1002 SPEED_TEST_COMPLETED",
		"Download=487.2Mbps",
		"Upload=41.8Mbps",
		"Latency=18.6ms",
		"Jitter=2.9ms",
		"PacketLoss=0.0%",
		"Status=HEALTHY",
		"TestServer=example",
		"Duration=12.4s",
	}, "\n")
	if got := ev.Text(); got != want {
		t.Errorf("text format mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestJSONLinesRoundTrip(t *testing.T) {
	ev := New(ThreatIntelligenceMatch).
		WithProcess("example.exe", 4132).
		WithDestination("203.0.113.20:443").
		WithField("ThreatSource", "ImportedFeed").
		WithField("Confidence", "High")
	b, err := ev.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\n") {
		t.Fatal("JSON Lines record must not contain a newline")
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out["event"] != "THREAT_INTELLIGENCE_MATCH" || out["severity"] != "WARNING" {
		t.Errorf("unexpected decoded event: %v", out)
	}
	if out["event_id"].(float64) != 5102 {
		t.Errorf("unexpected event id: %v", out["event_id"])
	}
}

// TestLogInjectionIsNeutralised is the important security property of the log format:
// a hostile process name must not be able to forge a second log record.
func TestLogInjectionIsNeutralised(t *testing.T) {
	hostile := "evil\n2026-08-24T00:00:00-05:00 INFO IPULSE-1002 SPEED_TEST_COMPLETED\nDownload=999Mbps"
	ev := New(NewExternalDestination).WithField("Process", hostile)
	text := ev.Text()
	if lines := strings.Count(text, "\n"); lines != 1 {
		t.Fatalf("expected exactly one body line, got %d:\n%s", lines, text)
	}
	if strings.Contains(text, "Download=999Mbps\n") {
		t.Fatal("injected record survived sanitisation")
	}
	if !strings.Contains(text, "\\n") {
		t.Fatal("newline was not escaped")
	}
}

func TestSeverityParsing(t *testing.T) {
	for in, want := range map[string]Severity{
		"debug": Debug, "INFO": Info, "notice": Notice, "warn": Warning,
		"WARNING": Warning, "error": Error, "crit": Critical, "CRITICAL": Critical,
	} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("expected error for unknown severity")
	}
}

func TestFormatRateAndBytes(t *testing.T) {
	if got := FormatRate(487_200_000); got != "487.2Mbps" {
		t.Errorf("FormatRate = %q", got)
	}
	if got := FormatRate(2_500_000_000); got != "2.50Gbps" {
		t.Errorf("FormatRate = %q", got)
	}
	if got := FormatBytes(5 * 1024 * 1024); got != "5.0MiB" {
		t.Errorf("FormatBytes = %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0:                        "0s",
		1500 * time.Nanosecond:   "1.5us",
		186 * time.Millisecond:   "186ms",
		12400 * time.Millisecond: "12.4s",
		252 * time.Second:        "4m12s",
		90 * time.Minute:         "1h30m",
	}
	for in, want := range cases {
		if got := FormatDuration(in); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestMarkdownGeneration(t *testing.T) {
	md := Markdown()
	for _, want := range []string{"# iPulse Event Catalog", "IPULSE-1002 SPEED_TEST_COMPLETED", "9000-9999"} {
		if !strings.Contains(md, want) {
			t.Errorf("generated catalog missing %q", want)
		}
	}
}
