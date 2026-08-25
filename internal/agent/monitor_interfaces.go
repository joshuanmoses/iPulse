package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/interfaces"
	"github.com/ipulse/ipulse/internal/platform"
)

// interfaceMonitor tracks interface, route, resolver and wireless state. It is the
// source of the "which interface and gateway are we using" facts that the connectivity
// diagnostics, the traffic monitor and the public-IP monitor all depend on.
type interfaceMonitor struct {
	a       *Agent
	tracker *interfaces.Tracker
	// wifiGate applies persistence to weak-signal reporting so a single bad sample on a
	// moving laptop does not raise an event.
	wifiGate *gate
}

func newInterfaceMonitor(a *Agent) *interfaceMonitor {
	return &interfaceMonitor{
		a:        a,
		tracker:  interfaces.NewTracker(a.cfg.Traffic.ErrorRateThreshold),
		wifiGate: a.newGate(),
	}
}

func (m *interfaceMonitor) Name() string { return "interfaces" }

func (m *interfaceMonitor) Tasks() []Task {
	tasks := []Task{{
		Name:       "interfaces",
		Interval:   m.a.cfg.Monitoring.InterfaceInterval.D(),
		Timeout:    20 * time.Second,
		Jitter:     m.a.cfg.Monitoring.Jitter.D(),
		RunOnStart: true,
		Fn:         m.collect,
	}}
	if m.a.cfg.WiFi.Enabled {
		tasks = append(tasks, Task{
			Name:       "wifi",
			Interval:   m.a.cfg.Monitoring.WiFiInterval.D(),
			Timeout:    15 * time.Second,
			Jitter:     m.a.cfg.Monitoring.Jitter.D(),
			RunOnStart: true,
			Fn:         m.collectWiFi,
		})
	}
	return tasks
}

func (m *interfaceMonitor) collect(ctx context.Context) error {
	snap, err := interfaces.Collect(m.a.plat)
	if err != nil {
		return err
	}
	changes := m.tracker.Observe(snap)

	// Persist the interface inventory and update the shared state.
	for _, i := range snap.Interfaces {
		isDefault := snap.DefaultRoute != nil && snap.DefaultRoute.Interface == i.Name
		if err := m.a.db.UpsertInterface(ctx, database.Interface{
			Name:      i.Name,
			Type:      i.Type,
			MAC:       i.MAC,
			MTU:       i.MTU,
			SpeedMbps: i.SpeedMbps,
			Addresses: strings.Join(i.AddrStrings(), ","),
			Up:        i.Up && i.Running,
			Wireless:  i.Type == platform.IfaceWireless,
			IsDefault: isDefault,
		}); err != nil {
			return err
		}
	}

	m.a.state.Update(func(s *Snapshot) {
		s.VPNActive = snap.VPNActive
		s.DNSServers = nil
		for _, ap := range snap.DNSServers {
			s.DNSServers = append(s.DNSServers, ap.String())
		}
		if snap.DefaultRoute != nil {
			s.Interface = snap.DefaultRoute.Interface
			if snap.DefaultRoute.Gateway.IsValid() {
				s.Gateway = snap.DefaultRoute.Gateway.String()
			} else {
				s.Gateway = ""
			}
		} else {
			s.Interface, s.Gateway = "", ""
		}
		if snap.DefaultIface != nil {
			s.InterfaceType = snap.DefaultIface.Type
			if addr, ok := snap.DefaultIface.PrimaryAddr(); ok {
				s.LocalIP = addr.String()
			}
		}
	})

	for _, c := range changes {
		m.emitChange(c, snap)
	}
	return nil
}

// emitChange maps a tracked change onto its catalogued event.
func (m *interfaceMonitor) emitChange(c interfaces.Change, snap interfaces.Snapshot) {
	fields := events.Fields{}.Add("Interface", c.Interface)
	for _, f := range c.Fields {
		if f[1] != "" {
			fields = fields.Add(f[0], f[1])
		}
	}

	switch c.Kind {
	case interfaces.InterfaceUp:
		m.a.log.Emit(events.New(events.InterfaceUp).WithFields(fields))
	case interfaces.InterfaceDown:
		m.a.log.Emit(events.New(events.InterfaceDown).WithFields(fields))
	case interfaces.AddressesChanged:
		m.a.log.Emit(events.New(events.IPAddressChanged).WithFields(
			fields.Add("Previous", c.Previous).Add("Current", c.Current)))
	case interfaces.LinkSpeedChanged:
		m.a.log.Emit(events.New(events.LinkSpeedChanged).WithFields(
			fields.Add("PreviousSpeed", c.Previous).Add("CurrentSpeed", c.Current)))
	case interfaces.DefaultIfaceChange:
		m.a.log.Emit(events.New(events.InterfaceChanged).WithFields(
			fields.Add("Previous", c.Previous).Add("Current", c.Current)))
	case interfaces.GatewayChanged:
		m.a.log.Emit(events.New(events.DefaultGatewayChange).WithFields(
			fields.Add("PreviousGateway", c.Previous).Add("NewGateway", c.Current)))
	case interfaces.DNSServersChanged:
		m.a.log.Emit(events.New(events.DNSServerChanged).WithFields(
			fields.Add("Previous", c.Previous).Add("Current", c.Current)))
	case interfaces.VPNStateChanged:
		m.a.log.Emit(events.New(events.VPNStateChanged).WithFields(fields))
	case interfaces.WiFiConnected:
		m.a.log.Emit(events.New(events.WiFiConnected).WithFields(fields))
	case interfaces.WiFiDisconnected:
		m.a.log.Emit(events.New(events.WiFiDisconnected).WithFields(fields))
	case interfaces.WiFiNetworkChanged:
		m.a.log.Emit(events.New(events.WiFiSSIDChanged).WithFields(fields))
	case interfaces.ErrorsRising:
		m.a.log.Emit(events.New(events.InterfaceErrorsRising).WithFields(fields))
	}
}

// collectWiFi samples wireless telemetry and reports weak signal.
func (m *interfaceMonitor) collectWiFi(ctx context.Context) error {
	links, err := m.a.plat.Wireless()
	if err != nil {
		// Absent wireless hardware is normal; report it once at debug level so the
		// reason is discoverable without filling the log.
		m.a.once("wifi-unavailable", func() {
			m.a.log.Emit(events.New(events.WiFiMonitoringUnavail).
				WithField("Reason", err).
				WithField("Platform", m.a.caps.Platform))
		})
		return nil
	}

	now := time.Now()
	active := m.a.state.CurrentInterface()
	for _, l := range links {
		if err := m.a.db.InsertWiFiSample(ctx, database.WiFiSample{
			Time: now, Interface: l.Interface, SSID: l.SSID, BSSID: l.BSSID,
			SignalDBM: l.SignalDBM, SignalPct: l.SignalPct, LinkMbps: l.LinkMbps,
			RxMbps: l.RxMbps, FrequencyMHz: l.FrequencyMHz, Channel: l.Channel,
			Band: l.Band, NoiseDBM: l.NoiseDBM,
		}); err != nil {
			return err
		}
		if err := m.a.db.InsertMeasurements(ctx, []database.Measurement{
			{Time: now, Metric: database.MetricWiFiSignalDBM, Value: float64(l.SignalDBM),
				Unit: "dBm", Target: l.Interface, OK: true},
			{Time: now, Metric: database.MetricWiFiLinkMbps, Value: l.LinkMbps,
				Unit: "Mbps", Target: l.Interface, OK: true},
		}); err != nil {
			return err
		}

		if l.Interface == active || active == "" {
			link := l
			m.a.state.Update(func(s *Snapshot) {
				s.WiFi = &WiFiState{
					Interface: link.Interface, SSID: link.SSID, BSSID: link.BSSID,
					SignalDBM: link.SignalDBM, SignalPct: link.SignalPct,
					LinkMbps: link.LinkMbps, FrequencyMHz: link.FrequencyMHz,
					Channel: link.Channel, Band: link.Band,
				}
			})
		}

		// Weak signal is reported with persistence: laptops move, and a single low
		// sample is not a problem worth an event.
		weak := l.SignalDBM != 0 && l.SignalDBM <= m.a.cfg.WiFi.WeakSignalDBM
		d := m.wifiGate.Observe("wifi-weak:"+l.Interface, weak, now)
		switch {
		case d.Fire:
			loss, _, _ := m.a.db.LatestMeasurement(ctx, database.MetricPacketLossPct, "")
			m.a.log.Emit(events.New(events.WiFiSignalDegraded).
				WithField("Interface", l.Interface).
				WithField("SSID", l.SSID).
				WithField("Signal", signalField(l.SignalDBM)).
				WithFields(events.Fields{}.AddPercent("SignalPercent", float64(l.SignalPct))).
				WithField("Threshold", signalField(m.a.cfg.WiFi.WeakSignalDBM)).
				WithFields(events.Fields{}.AddUnit("LinkSpeed", l.LinkMbps, "Mbps")).
				WithFields(events.Fields{}.AddPercent("PacketLoss", loss.Value)).
				WithField("Channel", l.Channel))
		case d.Recovered:
			m.a.log.Emit(events.New(events.WiFiConnected).WithSeverity(events.Notice).
				WithField("Interface", l.Interface).
				WithField("SSID", l.SSID).
				WithField("Signal", signalField(l.SignalDBM)).
				WithField("Detail", "signal recovered above the weak-signal threshold").
				WithField("Duration", d.Duration))
		}
	}
	return nil
}

func signalField(dbm int) string {
	return jsonNumber(dbm) + "dBm"
}

func jsonNumber(v int) string {
	b, _ := json.Marshal(v)
	return string(b)
}
