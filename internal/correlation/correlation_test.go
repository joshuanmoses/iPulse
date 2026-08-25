package correlation

import (
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

func eventSignal(t time.Time, code int, fields map[string]string) Signal {
	def, _ := events.Lookup(code)
	return Signal{
		Time: t, Kind: KindEvent, Code: code, Name: def.Name,
		Fields: fields, EventID: int64(code),
	}
}

func sampleSignal(t time.Time, metric string, value float64) Signal {
	return Signal{Time: t, Kind: KindSample, Name: metric, Value: value}
}

// TestSaturationCorrelation is the worked example from the requirements: an upload spike
// plus rising latency plus loss plus falling download must produce one conclusion.
func TestSaturationCorrelation(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-60*time.Second), events.BandwidthSpikeUpload,
		map[string]string{"CurrentRate": "94.0Mbps", "TopProcess": "backup-agent"}))
	e.Observe(eventSignal(now.Add(-40*time.Second), events.LatencyDegradation,
		map[string]string{"CurrentLatency": "73ms", "Deviation": "305%"}))
	e.Observe(eventSignal(now.Add(-30*time.Second), events.PacketLossDetected,
		map[string]string{"PacketLoss": "2.1%"}))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricLatencyMS, 73))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricPacketLossPct, 2.1))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricTxBps, 94e6))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected the saturation rule to fire")
	}
	if match.Rule.Conclusion != events.LocalBandwidthSaturation {
		t.Errorf("conclusion = %d, want LOCAL_BANDWIDTH_SATURATION", match.Rule.Conclusion)
	}
	if len(match.Evidence) != 3 {
		t.Errorf("expected three pieces of evidence, got %v", match.Evidence)
	}
	if len(match.SuppressID) == 0 {
		t.Error("expected the contributing events to be marked for suppression")
	}
	fields := match.Fields.Map()
	if fields["Direction"] != "upload" {
		t.Errorf("direction = %q, want upload", fields["Direction"])
	}
	if fields["TopProcess"] != "backup-agent" {
		t.Errorf("top process = %q", fields["TopProcess"])
	}
	if fields["PacketLoss"] != "2.1%" {
		t.Errorf("packet loss = %q", fields["PacketLoss"])
	}
}

// TestSaturationNeedsAllConditions is the property that keeps correlation honest: a
// bandwidth spike on its own is not saturation.
func TestSaturationNeedsAllConditions(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-30*time.Second), events.BandwidthSpikeUpload,
		map[string]string{"CurrentRate": "94.0Mbps"}))
	if _, ok := e.Evaluate(now); ok {
		t.Fatal("a bandwidth spike alone must not be reported as saturation")
	}

	// Adding latency degradation is still not enough without loss or a throughput drop.
	e.Observe(eventSignal(now.Add(-20*time.Second), events.LatencyDegradation,
		map[string]string{"CurrentLatency": "73ms"}))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricPacketLossPct, 0))
	if match, ok := e.Evaluate(now); ok {
		t.Fatalf("two of three conditions must not fire the rule, got %s", match.Rule.Name)
	}
}

func TestWiFiDegradationCorrelation(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-50*time.Second), events.WiFiSignalDegraded,
		map[string]string{"SSID": "Home", "Signal": "-84dBm"}))
	e.Observe(eventSignal(now.Add(-40*time.Second), events.PacketLossDetected,
		map[string]string{"PacketLoss": "4.0%"}))
	e.Observe(sampleSignal(now.Add(-30*time.Second), database.MetricGatewayRTTMS, 45))
	e.Observe(sampleSignal(now.Add(-30*time.Second), database.MetricWiFiSignalDBM, -84))
	e.Observe(sampleSignal(now.Add(-30*time.Second), database.MetricWiFiLinkMbps, 6))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected the Wi-Fi rule to fire")
	}
	if match.Rule.Conclusion != events.WiFiDegradation {
		t.Errorf("conclusion = %d, want WIFI_DEGRADATION", match.Rule.Conclusion)
	}
	fields := match.Fields.Map()
	if fields["SSID"] != "Home" || fields["GatewayRTT"] != "45.0ms" {
		t.Errorf("unexpected fields: %v", fields)
	}
}

// TestWiFiRuleDeclinesWhenLocalHopIsFine is the discrimination that matters: weak signal
// with a fast gateway means the loss is upstream, not on the radio.
func TestWiFiRuleDeclinesWhenLocalHopIsFine(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-50*time.Second), events.WiFiSignalDegraded,
		map[string]string{"SSID": "Home", "Signal": "-72dBm"}))
	e.Observe(eventSignal(now.Add(-40*time.Second), events.LatencyDegradation,
		map[string]string{"CurrentLatency": "180ms"}))
	e.Observe(sampleSignal(now.Add(-30*time.Second), database.MetricGatewayRTTMS, 2))

	if match, ok := e.Evaluate(now); ok && match.Rule.Conclusion == events.WiFiDegradation {
		t.Error("a healthy gateway RTT must not be attributed to Wi-Fi")
	}
}

func TestDNSSlownessCorrelation(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-30*time.Second), events.DNSSlowResponse,
		map[string]string{"Server": "192.168.1.1:53", "Name": "www.google.com", "ResponseTime": "820ms"}))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricLatencyMS, 18))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricDNSMS, 820))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected the DNS rule to fire")
	}
	if match.Rule.Conclusion != events.DNSResponseDegradation {
		t.Errorf("conclusion = %d", match.Rule.Conclusion)
	}
	if got := match.Fields.Map()["CurrentDNS"]; got != "820.0ms" {
		t.Errorf("CurrentDNS = %q", got)
	}
}

// TestDNSRuleDeclinesDuringAnOutage keeps the engine from explaining an outage as slow
// DNS, which would be actively misleading.
func TestDNSRuleDeclinesDuringAnOutage(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-40*time.Second), events.DNSSlowResponse,
		map[string]string{"Server": "192.168.1.1:53"}))
	e.Observe(eventSignal(now.Add(-30*time.Second), events.OutageStarted,
		map[string]string{"Classification": "ISP_OUTAGE"}))

	if match, ok := e.Evaluate(now); ok && match.Rule.Conclusion == events.DNSResponseDegradation {
		t.Error("slow DNS must not be the conclusion while an outage is open")
	}
}

func TestVPNRoutingCorrelation(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-20*time.Second), events.VPNStateChanged,
		map[string]string{"VPNActive": "true", "Interface": "tun0"}))
	e.Observe(eventSignal(now.Add(-18*time.Second), events.PublicIPChanged,
		map[string]string{"PreviousIP": "203.0.113.41", "NewIP": "198.51.100.7"}))
	e.Observe(eventSignal(now.Add(-17*time.Second), events.DNSServerChanged,
		map[string]string{"Current": "10.8.0.1:53"}))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected the VPN rule to fire")
	}
	fields := match.Fields.Map()
	if fields["PublicIP"] != "198.51.100.7" || fields["PreviousPublicIP"] != "203.0.113.41" {
		t.Errorf("unexpected fields: %v", fields)
	}
	// The individual notices are absorbed into the one conclusion.
	if len(match.SuppressID) < 2 {
		t.Errorf("expected the contributing notices to be suppressed, got %v", match.SuppressID)
	}
}

func TestISPDegradationCorrelation(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-30*time.Second), events.DownloadDegradation,
		map[string]string{"Deviation": "-62%", "CurrentDownload": "180.0Mbps"}))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricRxBps, 5e6))
	e.Observe(sampleSignal(now.Add(-20*time.Second), database.MetricDownloadMbps, 180))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected the ISP degradation rule to fire")
	}
	if match.Cause != "UPSTREAM OR ISP PERFORMANCE DEGRADATION" {
		t.Errorf("cause = %q", match.Cause)
	}
}

// TestISPRuleDeclinesWhenSaturated is the ordering property: local saturation explains a
// throughput drop, so the ISP must not be blamed.
func TestISPRuleDeclinesWhenSaturated(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-40*time.Second), events.DownloadDegradation,
		map[string]string{"Deviation": "-62%"}))
	e.Observe(eventSignal(now.Add(-35*time.Second), events.BandwidthSpikeDownload,
		map[string]string{"CurrentRate": "480Mbps"}))
	e.Observe(eventSignal(now.Add(-30*time.Second), events.LatencyDegradation,
		map[string]string{"CurrentLatency": "90ms"}))
	e.Observe(sampleSignal(now.Add(-25*time.Second), database.MetricPacketLossPct, 1.5))

	match, ok := e.Evaluate(now)
	if !ok {
		t.Fatal("expected a rule to fire")
	}
	if match.Rule.Conclusion != events.LocalBandwidthSaturation {
		t.Errorf("expected saturation to win, got %s", match.Rule.Name)
	}
}

func TestEngineIgnoresItsOwnConclusions(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	// Feeding a conclusion back in must not become an input signal.
	e.Observe(eventSignal(now, events.LocalBandwidthSaturation, map[string]string{"Direction": "upload"}))
	view := NewView(now, e.window.Snapshot(now))
	if view.HasEvent(events.LocalBandwidthSaturation) {
		t.Error("the engine must not ingest its own conclusions")
	}
}

func TestCooldownPreventsRepeats(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	now := time.Now()

	feed := func(at time.Time) {
		e.Observe(eventSignal(at, events.BandwidthSpikeUpload, map[string]string{"CurrentRate": "94Mbps"}))
		e.Observe(eventSignal(at, events.LatencyDegradation, map[string]string{"CurrentLatency": "73ms"}))
		e.Observe(eventSignal(at, events.PacketLossDetected, map[string]string{"PacketLoss": "2.1%"}))
	}
	feed(now)
	if _, ok := e.Evaluate(now); !ok {
		t.Fatal("expected the first evaluation to fire")
	}
	feed(now.Add(time.Minute))
	if match, ok := e.Evaluate(now.Add(time.Minute)); ok && match.Rule.Name == "local-bandwidth-saturation" {
		t.Error("the cooldown should suppress an immediate repeat")
	}
	// After the cooldown it may fire again.
	feed(now.Add(11 * time.Minute))
	if _, ok := e.Evaluate(now.Add(11 * time.Minute)); !ok {
		t.Error("expected the rule to fire again after its cooldown")
	}
}

// TestWindowExpiry is what stops unrelated events hours apart from being correlated.
func TestWindowExpiry(t *testing.T) {
	e := NewEngine(time.Minute, DefaultRules())
	now := time.Now()

	e.Observe(eventSignal(now.Add(-10*time.Minute), events.BandwidthSpikeUpload, nil))
	e.Observe(eventSignal(now, events.LatencyDegradation, nil))
	e.Observe(eventSignal(now, events.PacketLossDetected, nil))

	if _, ok := e.Evaluate(now); ok {
		t.Error("signals outside the window must not be correlated")
	}
}

func TestDisabledEngineFiresNothing(t *testing.T) {
	e := NewEngine(3*time.Minute, DefaultRules())
	e.SetEnabled(false)
	now := time.Now()
	e.Observe(eventSignal(now, events.BandwidthSpikeUpload, nil))
	e.Observe(eventSignal(now, events.LatencyDegradation, nil))
	e.Observe(eventSignal(now, events.PacketLossDetected, nil))
	if _, ok := e.Evaluate(now); ok {
		t.Error("a disabled engine must not fire")
	}
}

func TestRuleMetadata(t *testing.T) {
	e := NewEngine(time.Minute, DefaultRules())
	if len(e.RuleNames()) != len(DefaultRules()) {
		t.Errorf("rule names = %v", e.RuleNames())
	}
	if e.WindowSize() != time.Minute {
		t.Errorf("window = %v", e.WindowSize())
	}
	for _, r := range e.Rules() {
		if r.Name == "" || r.Conclusion == 0 || r.Cause == "" || len(r.Requires) == 0 {
			t.Errorf("incomplete rule: %+v", r)
		}
		if _, ok := events.Lookup(r.Conclusion); !ok {
			t.Errorf("rule %s concludes with an uncatalogued event %d", r.Name, r.Conclusion)
		}
	}
}
