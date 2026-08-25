package agent

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/lateral"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/platform"
)

// lateralMonitor watches for scanning and sweep behaviour toward the local network.
//
// Findings are phrased as possibilities with a stated confidence and a named process,
// because the same patterns are produced by approved tooling. An event that says
// "possible lateral scanning behaviour, process=nessus-agent, confidence=low" is useful;
// one that says "compromise detected" is not.
type lateralMonitor struct {
	a        *Agent
	detector *lateral.Detector
}

func newLateralMonitor(a *Agent) *lateralMonitor {
	return &lateralMonitor{
		a: a,
		detector: lateral.New(lateral.Config{
			Window:             a.cfg.Lateral.Window.D(),
			HostSweepThreshold: a.cfg.Lateral.HostSweepThreshold,
			PortScanThreshold:  a.cfg.Lateral.PortScanThreshold,
			FailedThreshold:    a.cfg.Lateral.FailedConnectionThreshold,
			AdminPorts:         a.cfg.Lateral.AdminPorts,
			AdminSweepHosts:    a.cfg.Lateral.AdminSweepHosts,
			AllowProcesses:     a.cfg.Lateral.AllowProcesses,
			Cooldown:           a.cfg.Alerts.Cooldown.D(),
		}),
	}
}

func (m *lateralMonitor) Name() string { return "lateral" }

// Tasks returns none: the detector runs from the connection snapshots.
func (m *lateralMonitor) Tasks() []Task { return nil }

// Connections implements connectionConsumer.
func (m *lateralMonitor) Connections(ctx context.Context, snap network.Snapshot) error {
	if !m.a.cfg.Lateral.Enabled {
		return nil
	}
	obs := make([]lateral.Observation, 0, len(snap.Connections))
	for _, c := range snap.Connections {
		if !c.Internal || c.RemoteIP == "" {
			continue
		}
		addr, err := netip.ParseAddr(c.RemoteIP)
		if err != nil {
			continue
		}
		// The host's own addresses are not lateral targets.
		if addr.IsLoopback() {
			continue
		}
		obs = append(obs, lateral.Observation{
			Time:     snap.Time,
			Host:     addr,
			Port:     c.RemotePort,
			Process:  c.Process,
			PID:      c.PID,
			Exe:      c.Exe,
			User:     c.User,
			Protocol: c.Protocol,
			// SYN_SENT means the handshake has not completed, which is the signal that
			// separates probing from use.
			Failed: c.State == platform.StateSynSent || c.State == platform.StateClosed,
		})
	}

	for _, f := range m.detector.Observe(obs, snap.Time) {
		m.report(f)
	}
	return nil
}

func (m *lateralMonitor) report(f lateral.Finding) {
	fields := events.Fields{}.
		Add("Process", f.Process).
		Add("Window", f.Window).
		Add("Attempts", f.Attempts).
		Add("FailedConnections", f.Failed).
		Add("Confidence", strings.Title(f.Confidence)).
		Add("Interpretation", f.Interpretation)
	if f.PID > 0 {
		fields = fields.Add("PID", f.PID)
	}
	if f.Exe != "" {
		fields = fields.Add("ExecutablePath", f.Exe)
	}
	if f.User != "" {
		fields = fields.Add("User", f.User)
	}
	if f.Sequential {
		fields = fields.Add("Sequential", true)
	}
	if len(f.Subnets) > 0 {
		fields = fields.Add("Subnets", strings.Join(f.Subnets, ","))
	}

	switch f.Kind {
	case lateral.HostSweep:
		m.a.log.Emit(events.New(events.InternalHostSweep).
			WithField("DistinctHosts", f.DistinctHosts).
			WithField("Ports", joinInts(f.Ports)).
			WithField("Hosts", strings.Join(f.Hosts, ",")).
			WithFields(fields))
	case lateral.PortScan:
		m.a.log.Emit(events.New(events.PossiblePortScan).
			WithField("TargetHost", f.TargetHost).
			WithField("DistinctPorts", f.DistinctPorts).
			WithField("Ports", joinInts(f.Ports)).
			WithFields(fields).
			WithDestination(f.TargetHost))
	case lateral.AdminSweep:
		m.a.log.Emit(events.New(events.RemoteAdminProtoSweep).
			WithField("Protocols", strings.Join(f.AdminProtocols, ",")).
			WithField("DistinctHosts", f.DistinctHosts).
			WithField("Ports", joinInts(f.Ports)).
			WithField("Hosts", strings.Join(f.Hosts, ",")).
			WithFields(fields))
	case lateral.RepeatedFailures:
		m.a.log.Emit(events.New(events.RepeatedInternalFailures).
			WithField("FailedAttempts", f.Failed).
			WithField("DistinctHosts", f.DistinctHosts).
			WithField("Ports", joinInts(f.Ports)).
			WithFields(fields))
	case lateral.AbnormalLateral:
		m.a.log.Emit(events.New(events.AbnormalLateralConns).
			WithField("DistinctHosts", f.DistinctHosts).
			WithField("Connections", f.Attempts).
			WithFields(fields))
	}
}

func joinInts(in []int) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}
