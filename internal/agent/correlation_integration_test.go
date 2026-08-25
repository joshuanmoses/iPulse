package agent

import (
	"context"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// TestCorrelationReplacesSymptomsWithAConclusion drives the whole pipeline: individual
// detectors emit symptom events, and the correlation monitor turns them into one
// conclusion while marking the symptoms as absorbed.
func TestCorrelationReplacesSymptomsWithAConclusion(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Correlation.Enabled = true
		c.Correlation.SuppressContributing = true
	})
	corr := newCorrelationMonitor(a)
	ctx := context.Background()
	now := time.Now()

	// The symptoms a saturated link produces, emitted the way the detectors emit them.
	a.log.Emit(events.New(events.BandwidthSpikeUpload).
		WithField("Interface", "eth0").
		WithField("CurrentRate", "94.0Mbps").
		WithField("TopProcess", "backup-agent"))
	a.log.Emit(events.New(events.LatencyDegradation).
		WithField("CurrentLatency", "73.0ms").
		WithField("Deviation", "305%"))
	a.log.Emit(events.New(events.PacketLossDetected).
		WithField("PacketLoss", "2.1%"))
	a.log.Flush()

	// Feed the measurements the rule reads for context.
	corr.Samples(ctx, []sample{
		{Time: now, Metric: database.MetricLatencyMS, Value: 73, Valid: true},
		{Time: now, Metric: database.MetricPacketLossPct, Value: 2.1, Valid: true},
		{Time: now, Metric: database.MetricTxBps, Value: 94e6, Valid: true},
	})

	if err := corr.run(ctx); err != nil {
		t.Fatalf("correlation run: %v", err)
	}

	ev := requireEvent(t, a, events.LocalBandwidthSaturation)
	if ev.Fields["ProbableCause"] != "LOCAL BANDWIDTH SATURATION" {
		t.Errorf("ProbableCause = %q", ev.Fields["ProbableCause"])
	}
	if ev.Fields["Direction"] != "upload" {
		t.Errorf("Direction = %q", ev.Fields["Direction"])
	}
	if ev.Fields["TopProcess"] != "backup-agent" {
		t.Errorf("TopProcess = %q", ev.Fields["TopProcess"])
	}
	// The evidence must name each contributing symptom, so the conclusion can be checked.
	evidence := ev.Fields["Evidence"]
	for _, want := range []string{"BANDWIDTH_SPIKE_UPLOAD", "LATENCY_DEGRADATION", "PACKET_LOSS_DETECTED"} {
		if !contains(evidence, want) {
			t.Errorf("Evidence %q does not mention %s", evidence, want)
		}
	}
	if ev.CorrelationID == "" {
		t.Error("the conclusion must carry a correlation id")
	}

	// The symptoms are now absorbed: the default event view shows the conclusion only.
	visible, err := a.db.QueryEvents(ctx, database.EventFilter{
		Codes: []int{events.BandwidthSpikeUpload, events.LatencyDegradation, events.PacketLossDetected},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 0 {
		t.Errorf("expected the contributing events to be suppressed, %d still visible", len(visible))
	}
	// They remain retrievable for forensics.
	all, err := a.db.QueryEvents(ctx, database.EventFilter{
		Codes:             []int{events.BandwidthSpikeUpload, events.LatencyDegradation, events.PacketLossDetected},
		IncludeSuppressed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("suppressed events must still be stored, found %d", len(all))
	}
	for _, e := range all {
		if e.CorrelationID != ev.CorrelationID {
			t.Errorf("suppressed event %s carries correlation id %q, want %q", e.Name, e.CorrelationID, ev.CorrelationID)
		}
	}
}

// TestCorrelationDoesNotFireOnASingleSymptom keeps the engine from turning one
// observation into a diagnosis.
func TestCorrelationDoesNotFireOnASingleSymptom(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) { c.Correlation.Enabled = true })
	corr := newCorrelationMonitor(a)
	ctx := context.Background()

	a.log.Emit(events.New(events.BandwidthSpikeUpload).WithField("CurrentRate", "94.0Mbps"))
	a.log.Flush()
	if err := corr.run(ctx); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, a, events.LocalBandwidthSaturation)
}

// TestCorrelationCanBeDisabled respects the configuration switch.
func TestCorrelationDisabled(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) { c.Correlation.Enabled = false })
	corr := newCorrelationMonitor(a)
	ctx := context.Background()

	a.log.Emit(events.New(events.BandwidthSpikeUpload).WithField("CurrentRate", "94.0Mbps"))
	a.log.Emit(events.New(events.LatencyDegradation).WithField("CurrentLatency", "73.0ms"))
	a.log.Emit(events.New(events.PacketLossDetected).WithField("PacketLoss", "2.1%"))
	a.log.Flush()
	if err := corr.run(ctx); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, a, events.LocalBandwidthSaturation)
}

// TestCorrelationVPNGrouping turns four separate notices into one explanation.
func TestCorrelationVPNGrouping(t *testing.T) {
	a := newTestAgent(t, func(c *config.Config) {
		c.Correlation.Enabled = true
		c.Correlation.SuppressContributing = true
	})
	corr := newCorrelationMonitor(a)
	ctx := context.Background()

	a.log.Emit(events.New(events.VPNStateChanged).
		WithField("VPNActive", "true").WithField("Interface", "tun0"))
	a.log.Emit(events.New(events.PublicIPChanged).
		WithField("PreviousIP", "203.0.113.41").WithField("NewIP", "198.51.100.7"))
	a.log.Emit(events.New(events.DNSServerChanged).WithField("Current", "10.8.0.1:53"))
	a.log.Flush()

	if err := corr.run(ctx); err != nil {
		t.Fatal(err)
	}
	ev := requireEvent(t, a, events.VPNRoutingChange)
	if ev.Fields["PublicIP"] != "198.51.100.7" {
		t.Errorf("PublicIP = %q", ev.Fields["PublicIP"])
	}
	if ev.Fields["Interface"] == "" && ev.Fields["DefaultRouteVia"] == "" {
		t.Error("expected the routing context to be reported")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfString(s, sub) >= 0)
}

func indexOfString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
