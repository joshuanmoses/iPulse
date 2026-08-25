package agent

import (
	"context"
	"net/netip"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/publicip"
)

// publicIPMonitor tracks the addresses this host presents to the Internet.
//
// A public IP change is normal on a dynamic connection, so it is reported as a notice
// with context (interface, VPN state, ASN) rather than as a security event. What makes it
// worth reporting is the correlation: an address change together with a route change and
// a resolver change is a VPN connecting, and an ASN change is the provider changing.
type publicIPMonitor struct {
	a        *Agent
	detector *publicip.Detector
	enricher *publicip.Enricher
	failGate *gate
}

func newPublicIPMonitor(a *Agent) *publicIPMonitor {
	var enricher *publicip.Enricher
	if a.cfg.PublicIP.ASNLookup {
		enricher = publicip.NewEnricher(a.cfg.PublicIP.ASNProviderURL, a.cfg.PublicIP.Timeout.D())
	}
	return &publicIPMonitor{
		a:        a,
		detector: publicip.NewDetector(a.cfg.PublicIP.Timeout.D()),
		enricher: enricher,
		failGate: a.newGate(),
	}
}

func (m *publicIPMonitor) Name() string { return "public-ip" }

func (m *publicIPMonitor) Tasks() []Task {
	return []Task{{
		Name:       "public-ip",
		Interval:   m.a.cfg.Monitoring.PublicIPInterval.D(),
		Timeout:    m.a.cfg.PublicIP.Timeout.D()*4 + 20*time.Second,
		Jitter:     m.a.cfg.Monitoring.Jitter.D(),
		RunOnStart: true,
		Fn:         m.run,
	}}
}

func (m *publicIPMonitor) run(ctx context.Context) error {
	if !m.a.state.Online() {
		// Discovery would fail during an outage and produce a misleading event.
		return nil
	}
	if err := m.check(ctx, publicip.IPv4, m.a.cfg.PublicIP.Providers); err != nil {
		return err
	}
	if len(m.a.cfg.PublicIP.IPv6Providers) > 0 {
		// IPv6 is optional and often unavailable; a failure here is not an error.
		_ = m.check(ctx, publicip.IPv6, m.a.cfg.PublicIP.IPv6Providers)
	}
	return nil
}

func (m *publicIPMonitor) check(ctx context.Context, family publicip.Family, providers []string) error {
	if len(providers) == 0 {
		return nil
	}
	results, err := m.detector.Detect(ctx, providers, family)
	if err != nil {
		// IPv6 simply not being available is not worth an event.
		if family == publicip.IPv4 {
			if d := m.failGate.Observe("public-ip-"+string(family), true, time.Now()); d.Fire {
				m.a.log.Emit(events.New(events.PublicIPUnavailable).
					WithField("Family", string(family)).
					WithField("ProvidersTested", len(providers)).
					WithField("Errors", err))
			}
		}
		return nil
	}
	m.failGate.Clear("public-ip-"+string(family), time.Now())

	addr, agreement, ok := publicip.Agree(results)
	if !ok {
		return nil
	}
	// With confirmation enabled, a single provider's answer is not enough to record a
	// change: CDNs and anycast services occasionally answer for the wrong client.
	confirmed := agreement >= 2 || !m.a.cfg.PublicIP.ConfirmChanges || len(providers) == 1

	previous, hadPrevious, err := m.a.db.LatestPublicIP(ctx, string(family))
	if err != nil {
		return err
	}
	if hadPrevious && previous.NewIP == addr.String() {
		m.updateState(family, addr, previous.ASN, previous.ASNOrg, previous.Country, previous.CGNAT)
		return nil
	}
	if hadPrevious && !confirmed {
		// Seen once but not corroborated: wait for the next cycle rather than record it.
		return nil
	}

	network := m.lookupNetwork(ctx, addr)
	snap := m.a.state.Snapshot()
	cgnat := publicip.IsCGNAT(addr)

	record := database.PublicIPRecord{
		Time: time.Now(), Family: string(family), NewIP: addr.String(),
		ASN: network.ASN, ASNOrg: network.Org, Country: network.Country,
		Interface: snap.Interface, VPNActive: snap.VPNActive, CGNAT: cgnat,
		Provider: providerOf(results, addr),
	}
	if hadPrevious {
		record.PreviousIP = previous.NewIP
	}
	if _, err := m.a.db.InsertPublicIP(ctx, record); err != nil {
		return err
	}
	m.updateState(family, addr, network.ASN, network.Org, network.Country, cgnat)

	// The first observation is the baseline, not a change.
	if !hadPrevious {
		m.a.log.Emit(events.New(events.PublicIPChanged).WithSeverity(events.Info).
			WithField("Family", string(family)).
			WithField("NewIP", addr.String()).
			WithField("Detail", "first observation").
			WithField("ASN", network.ASN).
			WithField("Organization", network.Org).
			WithField("Country", network.Country).
			WithField("Interface", snap.Interface).
			WithField("VPNActive", snap.VPNActive).
			WithField("CGNAT", cgnat).
			WithField("Provider", record.Provider))
	} else {
		m.a.log.Emit(events.New(events.PublicIPChanged).
			WithField("Family", string(family)).
			WithField("PreviousIP", previous.NewIP).
			WithField("NewIP", addr.String()).
			WithField("Interface", snap.Interface).
			WithField("ASN", network.ASN).
			WithField("Organization", network.Org).
			WithField("Country", network.Country).
			WithField("VPNActive", snap.VPNActive).
			WithField("Provider", record.Provider).
			WithField("CGNAT", cgnat).
			WithField("Confirmations", agreement))

		if previous.ASN != "" && network.ASN != "" && previous.ASN != network.ASN {
			m.a.log.Emit(events.New(events.ISPASNChanged).
				WithField("PreviousASN", previous.ASN).
				WithField("NewASN", network.ASN).
				WithField("PreviousOrg", previous.ASNOrg).
				WithField("NewOrg", network.Org).
				WithField("PublicIP", addr.String()).
				WithField("VPNActive", snap.VPNActive))
		}
	}

	if cgnat {
		m.a.once("cgnat-"+addr.String(), func() {
			m.a.log.Emit(events.New(events.PossibleCGNAT).
				WithField("PublicIP", addr.String()).
				WithField("LocalWANAddress", snap.LocalIP).
				WithField("Evidence", "the observed public address is inside 100.64.0.0/10, "+
					"the range carriers use between the customer and the Internet"))
		})
	}
	return nil
}

func (m *publicIPMonitor) lookupNetwork(ctx context.Context, addr netip.Addr) publicip.Network {
	if m.enricher == nil {
		return publicip.Network{}
	}
	network, err := m.enricher.Lookup(ctx, addr)
	if err != nil {
		m.a.once("asn-lookup-failed", func() {
			m.a.log.Emit(events.New(events.CollectorError).WithSeverity(events.Notice).
				WithField("Collector", "asn-lookup").
				WithField("Error", err))
		})
		return publicip.Network{}
	}
	return network
}

func (m *publicIPMonitor) updateState(family publicip.Family, addr netip.Addr, asn, org, country string, cgnat bool) {
	m.a.state.Update(func(s *Snapshot) {
		if family == publicip.IPv4 {
			s.PublicIPv4 = addr.String()
			s.CGNAT = cgnat
		} else {
			s.PublicIPv6 = addr.String()
		}
		if asn != "" {
			s.ASN = asn
		}
		if org != "" {
			s.ISP = org
		}
		if country != "" {
			s.Country = country
		}
	})
}

func providerOf(results []publicip.Result, addr netip.Addr) string {
	for _, r := range results {
		if r.Addr == addr {
			return r.Provider
		}
	}
	return ""
}
