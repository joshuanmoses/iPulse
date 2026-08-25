package agent

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	dnsmon "github.com/ipulse/ipulse/internal/dns"
	"github.com/ipulse/ipulse/internal/events"
)

// dnsMonitor measures name resolution.
//
// One name is resolved per cycle, round-robin through the configured list. Resolving
// every name every cycle would multiply the query load for no extra information, and
// rotating names avoids measuring a single cached answer forever.
type dnsMonitor struct {
	a      *Agent
	prober *dnsmon.Prober
	next   atomic.Uint64
	slow   *gate
	fail   *gate
}

func newDNSMonitor(a *Agent) *dnsMonitor {
	return &dnsMonitor{
		a: a,
		prober: dnsmon.New(dnsmon.Config{
			Timeout:   a.cfg.DNS.Timeout.D(),
			UseSystem: a.cfg.DNS.UseSystemResolver,
		}),
		slow: a.newGate(),
		fail: a.newGate(),
	}
}

func (m *dnsMonitor) Name() string { return "dns" }

func (m *dnsMonitor) Tasks() []Task {
	return []Task{{
		Name:       "dns",
		Interval:   m.a.cfg.Monitoring.DNSInterval.D(),
		Timeout:    m.a.cfg.DNS.Timeout.D()*4 + 5*time.Second,
		Jitter:     m.a.cfg.Monitoring.Jitter.D(),
		RunOnStart: true,
		Fn:         m.run,
	}}
}

// Prober exposes the DNS prober for the connectivity diagnostics.
func (m *dnsMonitor) Prober() *dnsmon.Prober { return m.prober }

func (m *dnsMonitor) run(ctx context.Context) error {
	cfg := m.a.cfg.DNS
	if len(cfg.Names) == 0 {
		return nil
	}
	name := cfg.Names[int(m.next.Add(1)-1)%len(cfg.Names)]

	servers := cfg.Servers
	if len(servers) == 0 {
		// Query what the system is actually configured to use, so a resolver change is
		// reflected immediately.
		if addrs, err := m.a.plat.DNSServers(); err == nil {
			servers = dnsmon.ServersFromAddrPorts(addrs)
		}
	}

	set := m.prober.Probe(ctx, name, servers)
	now := time.Now()

	var measurements []database.Measurement
	for _, r := range set.Results {
		measurements = append(measurements, database.Measurement{
			Time: now, Metric: database.MetricDNSMS, Value: r.MS(),
			Unit: "ms", Target: r.Server, OK: r.OK, Meta: r.Error,
		})
	}
	// The connection-level DNS figure is the fastest working resolver: that is what an
	// application actually experiences when several are configured.
	if set.AnyOK {
		measurements = append(measurements, database.Measurement{
			Time: now, Metric: database.MetricDNSMS,
			Value: float64(set.Fastest) / float64(time.Millisecond), Unit: "ms", OK: true,
		})
		m.a.state.Update(func(s *Snapshot) {
			s.DNSMS = float64(set.Fastest) / float64(time.Millisecond)
		})
	}
	if err := m.a.db.InsertMeasurements(ctx, measurements); err != nil {
		return err
	}
	m.a.publishSamples(now, sample{
		Metric: database.MetricDNSMS,
		Value:  float64(set.Fastest) / float64(time.Millisecond),
		Valid:  set.AnyOK,
	})

	m.report(ctx, set, name, now)
	return nil
}

func (m *dnsMonitor) report(ctx context.Context, set dnsmon.ProbeSet, name string, now time.Time) {
	switch {
	case set.AllFailed && set.Tested > 0:
		d := m.fail.Observe("dns-failure", true, now)
		if d.Fire {
			first := ""
			if len(set.Results) > 0 {
				first = set.Results[0].Error
			}
			m.a.log.Emit(events.New(events.DNSResolutionFailed).
				WithField("Name", name).
				WithField("ServersTested", set.Tested).
				WithField("ServersFailed", set.Failed).
				WithField("FailedServers", strings.Join(set.FailedServers(), ",")).
				WithField("Timeout", m.a.cfg.DNS.Timeout.D()).
				WithField("Error", first))
		}
	case set.Failed > 0:
		// Some resolvers answered and others did not: worth reporting, because the
		// configuration is degraded even though resolution still works.
		m.fail.Clear("dns-failure", now)
		d := m.a.dnsPartialGate.Observe("dns-partial", true, now)
		if d.Fire {
			m.a.log.Emit(events.New(events.DNSPartialFailure).
				WithField("Name", name).
				WithField("ServersTested", set.Tested).
				WithField("ServersFailed", set.Failed).
				WithField("FailedServers", strings.Join(set.FailedServers(), ",")).
				WithField("WorkingServers", strings.Join(set.WorkingServers(), ",")))
		}
	default:
		if d := m.fail.Clear("dns-failure", now); d.Recovered {
			m.a.log.Emit(events.New(events.DNSResolutionOK).WithSeverity(events.Notice).
				WithField("Name", name).
				WithField("Server", firstWorking(set)).
				WithField("ResponseTime", set.Fastest).
				WithField("Detail", "resolution recovered").
				WithField("Duration", d.Duration))
		}
		m.a.dnsPartialGate.Clear("dns-partial", now)
		m.a.log.Emit(events.New(events.DNSResolutionOK).
			WithField("Name", name).
			WithField("Server", firstWorking(set)).
			WithField("ResponseTime", set.Fastest).
			WithField("Answers", answerCount(set)).
			WithField("Protocol", "udp"))
	}

	// Absolute slow-response rule. Baseline-relative degradation is a separate detector.
	threshold := m.a.cfg.DNS.SlowThreshold.D()
	if threshold > 0 && set.AnyOK {
		d := m.slow.Observe("dns-slow", set.Fastest > threshold, now)
		if d.Fire {
			baseline, _, _ := m.a.db.LatestMeasurement(ctx, database.MetricDNSMS, "")
			m.a.log.Emit(events.New(events.DNSSlowResponse).
				WithField("Name", name).
				WithField("Server", firstWorking(set)).
				WithField("ResponseTime", set.Fastest).
				WithField("Threshold", threshold).
				WithFields(events.Fields{}.AddUnit("BaselineDNS", baseline.Value, "ms")).
				WithField("Consecutive", d.Consecutive))
		}
	}
}

func firstWorking(set dnsmon.ProbeSet) string {
	for _, r := range set.Results {
		if r.OK {
			return r.Server
		}
	}
	return ""
}

func answerCount(set dnsmon.ProbeSet) int {
	for _, r := range set.Results {
		if r.OK {
			return len(r.Answers)
		}
	}
	return 0
}
