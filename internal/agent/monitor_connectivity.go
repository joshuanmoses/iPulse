package agent

import (
	"context"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/connectivity"
	"github.com/ipulse/ipulse/internal/database"
	dnsmon "github.com/ipulse/ipulse/internal/dns"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/latency"
)

// connectivityMonitor owns the health check, the diagnostic ladder and the outage
// lifecycle.
//
// The flow is deliberately narrow: a cheap health check runs frequently, and only a
// failure escalates to the expensive layered diagnosis. That keeps the steady-state cost
// to three TCP handshakes every 15 seconds while still producing a full evidence record
// the moment something breaks.
type connectivityMonitor struct {
	a       *Agent
	engine  *connectivity.Engine
	tracker *connectivity.Tracker
	// outageID is the open outage row, zero when there is none.
	outageID int64
	// lastDiagnosis is reused by the CLI and API when reporting current state.
	lastDiagnosis connectivity.Diagnosis
}

func newConnectivityMonitor(a *Agent, lat *latency.Prober, dns *dnsmon.Prober) *connectivityMonitor {
	set := connectivity.Settings{
		Targets:         a.cfg.Connectivity.Targets,
		RequiredSuccess: a.cfg.Connectivity.RequiredSuccess,
		IPLiterals:      a.cfg.Connectivity.IPLiterals,
		HTTPSTargets:    a.cfg.Connectivity.HTTPSTargets,
		DNSNames:        a.cfg.DNS.Names,
		DNSServers:      a.cfg.DNS.Servers,
		FallbackDNS:     a.cfg.DNS.FallbackServers,
		GatewayMethod:   a.cfg.Connectivity.GatewayProbeMethod,
		GatewayTCPPorts: a.cfg.Connectivity.GatewayTCPPorts,
		ProbeTimeout:    a.cfg.Monitoring.ProbeTimeout.D(),
		WeakSignalDBM:   a.cfg.WiFi.WeakSignalDBM,
	}
	return &connectivityMonitor{
		a:      a,
		engine: connectivity.NewEngine(set, a.plat, lat, dns),
		tracker: connectivity.NewTracker(
			a.cfg.Connectivity.FailuresBeforeOutage,
			a.cfg.Connectivity.SuccessesBeforeRecovery),
	}
}

func (m *connectivityMonitor) Name() string { return "connectivity" }

func (m *connectivityMonitor) Tasks() []Task {
	return []Task{
		{
			Name:       "connectivity",
			Interval:   m.a.cfg.Monitoring.HealthInterval.D(),
			Timeout:    m.a.cfg.Monitoring.ProbeTimeout.D() + 10*time.Second,
			Jitter:     m.a.cfg.Monitoring.Jitter.D(),
			RunOnStart: true,
			Fn:         m.check,
		},
		{
			// On-demand full diagnosis, triggered by `ipulse diagnostics` or the API.
			Name:       "diagnostics",
			ManualOnly: true,
			Timeout:    2 * time.Minute,
			Fn: func(ctx context.Context) error {
				_, err := m.Diagnose(ctx, "manual")
				return err
			},
		},
	}
}

// Restore adopts an outage that was already open when the agent started, so a restart
// during an outage continues the same record instead of opening a second one.
func (m *connectivityMonitor) Restore(ctx context.Context) {
	outage, open, err := m.a.db.CurrentOutage(ctx)
	if err != nil || !open {
		return
	}
	m.outageID = outage.ID
	m.tracker.Resume(outage.Start, connectivity.Classification(outage.Classification))
	m.a.state.SetStatus(StatusOffline)
	m.a.log.Emit(events.New(events.OutageStarted).WithSeverity(events.Notice).
		WithField("Classification", outage.Classification).
		WithField("ProbableCause", outage.ProbableCause).
		WithField("Detail", "resuming an outage that was open when the agent started").
		WithField("Start", outage.Start).
		WithField("Evidence", "restored"))
}

func (m *connectivityMonitor) check(ctx context.Context) error {
	res := m.engine.HealthCheck(ctx)
	now := res.Time

	if err := m.a.db.InsertMeasurement(ctx, database.Measurement{
		Time: now, Metric: "health_check_ok", Value: boolValue(res.OK),
		Target: "", OK: true,
	}); err != nil {
		return err
	}

	if res.OK {
		m.a.log.Emit(events.New(events.ConnectivityCheckOK).
			WithField("Targets", res.Total).
			WithField("Succeeded", res.Succeeded).
			WithField("RTT", res.BestRTT).
			WithField("Method", "tcp"))
	} else {
		m.a.log.Emit(events.New(events.ConnectivityCheckFailed).
			WithField("Targets", res.Total).
			WithField("Succeeded", res.Succeeded).
			WithField("Failures", res.FailureNames()).
			WithField("Method", "tcp"))
	}

	// Status reflects the check immediately; the outage record waits for hysteresis.
	switch {
	case res.OK && res.Succeeded == res.Total:
		m.a.state.SetStatus(StatusOnline)
	case res.OK:
		m.a.state.SetStatus(StatusDegraded)
	}

	switch m.tracker.Record(res.OK, now) {
	case connectivity.TransitionOpen:
		return m.openOutage(ctx, res)
	case connectivity.TransitionClose:
		return m.closeOutage(ctx, now)
	}

	// While an outage is open, re-diagnose periodically: the cause can change (a DNS
	// failure that becomes a full ISP outage), and each run refines the record.
	if m.tracker.Open() && m.tracker.ConsecutiveFailures()%4 == 0 {
		if _, err := m.Diagnose(ctx, "outage-refresh"); err != nil {
			return err
		}
	}
	return nil
}

// openOutage escalates to full diagnostics and records the outage.
func (m *connectivityMonitor) openOutage(ctx context.Context, res connectivity.HealthResult) error {
	m.a.state.SetStatus(StatusOffline)

	diag, err := m.Diagnose(ctx, "health-check-failure")
	if err != nil {
		return err
	}

	// A diagnosis of HEALTHY here means the cheap check failed but the full ladder
	// succeeded, which happens when a single probe target is unavailable. That is not an
	// outage, and recording one would be wrong.
	if diag.Classification == connectivity.ClassHealthy {
		m.tracker.Record(true, time.Now())
		m.a.state.SetStatus(StatusDegraded)
		m.a.log.Emit(events.New(events.PartialConnectivity).
			WithField("EndpointsTested", res.Total).
			WithField("EndpointsReachable", res.Succeeded).
			WithField("Unreachable", res.FailureNames()).
			WithField("Evidence", diag.Evidence.Summary()).
			WithField("ProbableCause", "individual probe targets are unreachable while the connection is healthy"))
		return nil
	}

	ev := diag.Evidence
	id, err := m.a.db.OpenOutage(ctx, database.Outage{
		Start:          m.tracker.OpenedAt(),
		Classification: string(diag.Classification),
		ProbableCause:  diag.ProbableCause,
		Evidence:       ev.JSON(),
		Interface:      ev.InterfaceName,
		Gateway:        ev.Gateway,
	})
	if err != nil {
		return err
	}
	m.outageID = id
	m.tracker.SetClassification(diag.Classification)

	m.a.log.Emit(events.New(events.InternetConnectivityLost).
		WithField("GatewayReachable", ev.GatewayReachable).
		WithField("DNSReachable", ev.DNSResolves).
		WithField("ExternalIPReachable", ev.ExternalIPReachable()).
		WithField("HTTPSReachable", ev.HTTPSReachableAny()).
		WithField("InterfaceUp", ev.InterfaceUp).
		WithField("ProbableCause", string(diag.Classification)))

	m.a.log.Emit(events.New(events.OutageStarted).
		WithField("Classification", string(diag.Classification)).
		WithField("ProbableCause", diag.ProbableCause).
		WithField("Evidence", ev.Summary()).
		WithField("Interface", ev.InterfaceName).
		WithField("Gateway", ev.Gateway))

	// The specific cause gets its own catalogued event, so an operator can alert on
	// "DNS failure" separately from "ISP outage".
	m.emitCauseEvent(diag)
	return nil
}

// emitCauseEvent raises the event specific to the diagnosed cause.
func (m *connectivityMonitor) emitCauseEvent(diag connectivity.Diagnosis) {
	ev := diag.Evidence
	switch diag.Classification {
	case connectivity.ClassISPOutage:
		m.a.log.Emit(events.New(events.ISPOutage).
			WithField("GatewayReachable", ev.GatewayReachable).
			WithField("DNSReachable", ev.DNSResolves).
			WithField("EndpointsTested", ev.IPLiteralsTested+ev.HTTPSTested).
			WithField("EndpointsReachable", ev.IPLiteralsReachable+ev.HTTPSReachable).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassDNSFailure:
		m.a.log.Emit(events.New(events.DNSFailure).
			WithField("ServersTested", ev.DNSServersTested).
			WithField("ServersFailed", ev.DNSServersFailed).
			WithField("NamesTested", 1).
			WithField("ExternalIPReachable", ev.ExternalIPReachable()).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassGatewayFailure:
		m.a.log.Emit(events.New(events.GatewayFailure).
			WithField("Gateway", ev.Gateway).
			WithField("Interface", ev.InterfaceName).
			WithField("InterfaceUp", ev.InterfaceUp).
			WithField("LocalIP", ev.LocalIP).
			WithField("Method", ev.GatewayMethod).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassLocalInterfaceFail:
		m.a.log.Emit(events.New(events.LocalInterfaceFailure).
			WithField("Interfaces", ev.InterfaceName).
			WithField("InterfaceUp", ev.InterfaceUp).
			WithField("LocalIP", ev.LocalIP).
			WithField("DefaultRoute", ev.DefaultRoutePresent).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassPartialConnectivity:
		m.a.log.Emit(events.New(events.PartialConnectivity).
			WithField("EndpointsTested", ev.IPLiteralsTested+ev.HTTPSTested).
			WithField("EndpointsReachable", ev.IPLiteralsReachable+ev.HTTPSReachable).
			WithField("Unreachable", strings.Join(append(ev.UnreachableLiterals, ev.UnreachableHTTPS...), ",")).
			WithField("Evidence", ev.Summary()).
			WithField("ProbableCause", diag.ProbableCause))
	case connectivity.ClassRoutingFailure:
		m.a.log.Emit(events.New(events.RoutingFailure).
			WithField("DefaultRoute", ev.DefaultRoutePresent).
			WithField("Gateway", ev.Gateway).
			WithField("Interface", ev.InterfaceName).
			WithField("VPNActive", ev.VPNActive).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassWiFiDegradation:
		m.a.log.Emit(events.New(events.WiFiDegradation).
			WithField("Interface", ev.InterfaceName).
			WithField("Signal", signalField(ev.WiFiSignalDBM)).
			WithField("GatewayRTT", ev.GatewayRTTMS).
			WithField("ProbableCause", diag.ProbableCause).
			WithField("Evidence", ev.Summary()))
	case connectivity.ClassCaptivePortal:
		m.a.log.Emit(events.New(events.PartialConnectivity).
			WithField("ProbableCause", diag.ProbableCause).
			WithField("Evidence", ev.Summary()).
			WithField("CaptivePortalSuspected", true))
	}
}

func (m *connectivityMonitor) closeOutage(ctx context.Context, now time.Time) error {
	previous := m.tracker.Classification()
	var duration time.Duration

	if m.outageID != 0 {
		closed, err := m.a.db.CloseOutage(ctx, m.outageID, now)
		if err != nil {
			return err
		}
		duration = closed.Duration
		m.a.log.Emit(events.New(events.OutageEnded).
			WithField("Classification", closed.Classification).
			WithField("ProbableCause", closed.ProbableCause).
			WithField("Duration", closed.Duration).
			WithField("Start", closed.Start).
			WithField("End", now))
		m.outageID = 0
	}

	m.a.state.SetStatus(StatusOnline)
	m.a.state.Update(func(s *Snapshot) { s.CurrentOutage = nil })
	m.a.log.Emit(events.New(events.InternetRestored).
		WithField("OutageDuration", duration).
		WithField("PreviousCause", string(previous)).
		WithField("Targets", len(m.a.cfg.Connectivity.Targets)))
	return nil
}

// Diagnose runs the ladder and records the result.
func (m *connectivityMonitor) Diagnose(ctx context.Context, trigger string) (connectivity.Diagnosis, error) {
	diag := m.engine.Diagnose(ctx, trigger)
	m.lastDiagnosis = diag

	m.a.state.Update(func(s *Snapshot) {
		s.LastDiagnosis = string(diag.Classification)
		if diag.Evidence.InterfaceName != "" {
			s.Interface = diag.Evidence.InterfaceName
			s.InterfaceType = diag.Evidence.InterfaceType
		}
		if diag.Evidence.LocalIP != "" {
			s.LocalIP = diag.Evidence.LocalIP
		}
		if diag.Evidence.Gateway != "" {
			s.Gateway = diag.Evidence.Gateway
		}
		if diag.Evidence.GatewayRTTMS > 0 {
			s.GatewayRTTMS = diag.Evidence.GatewayRTTMS
		}
	})

	m.a.log.Emit(events.New(events.DiagnosticsCompleted).
		WithField("Classification", string(diag.Classification)).
		WithField("ProbableCause", diag.ProbableCause).
		WithField("Duration", diag.Duration).
		WithField("Trigger", diag.Trigger).
		WithField("Evidence", diag.Evidence.Summary()))
	return diag, nil
}

// LastDiagnosis returns the most recent diagnosis.
func (m *connectivityMonitor) LastDiagnosis() connectivity.Diagnosis { return m.lastDiagnosis }

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
