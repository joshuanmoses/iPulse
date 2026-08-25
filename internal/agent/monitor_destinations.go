package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/destinations"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/publicip"
)

// destinationMonitor maintains the history of remote endpoints and reports what is
// notable about them. It consumes the connection snapshots the connection monitor
// already collects, so the socket table is read once per cycle regardless of how many
// detectors need it.
type destinationMonitor struct {
	a        *Agent
	analyzer *destinations.Analyzer
	store    *destinationStore
	// enrichQueue holds destinations awaiting reverse DNS and ASN lookup, so a slow
	// lookup never delays the collection cycle.
	enrichQueue chan enrichRequest
}

type enrichRequest struct {
	id   int64
	addr netip.Addr
}

func newDestinationMonitor(a *Agent) *destinationMonitor {
	store := &destinationStore{db: a.db}
	return &destinationMonitor{
		a:     a,
		store: store,
		analyzer: destinations.New(destinations.Config{
			LearningPeriod:  a.cfg.Destinations.LearningPeriod.D(),
			NewWindow:       a.cfg.Destinations.NewDestinationWindow.D(),
			RarePercentile:  a.cfg.Destinations.RarePercentile,
			HighVolumeBytes: int64(a.cfg.Destinations.HighVolumeMB * 1024 * 1024),
			FanoutWindow:    a.cfg.Destinations.FanoutWindow.D(),
			FanoutThreshold: a.cfg.Destinations.FanoutThreshold,
			ExpectedPorts:   a.cfg.Destinations.ExpectedPorts,
		}, store, time.Now()),
		enrichQueue: make(chan enrichRequest, 256),
	}
}

func (m *destinationMonitor) Name() string { return "destinations" }

func (m *destinationMonitor) Tasks() []Task {
	return []Task{{
		// Enrichment runs on its own schedule so reverse DNS latency never delays the
		// connection cycle.
		Name:       "destination-enrichment",
		Interval:   30 * time.Second,
		Timeout:    25 * time.Second,
		RunOnStart: false,
		Fn:         m.enrich,
	}}
}

// Connections implements connectionConsumer.
func (m *destinationMonitor) Connections(ctx context.Context, snap network.Snapshot) error {
	obs := make([]destinations.Observation, 0, len(snap.Connections))
	for _, c := range snap.Connections {
		addr, err := netip.ParseAddr(c.RemoteIP)
		if err != nil {
			continue
		}
		obs = append(obs, destinations.Observation{
			Time: snap.Time, RemoteIP: addr, RemotePort: c.RemotePort, Protocol: c.Protocol,
			Process: c.Process, PID: c.PID, Exe: c.Exe, User: c.User,
			Internal: c.Internal, BytesSent: c.BytesSent, BytesRecv: c.BytesRecv, State: c.State,
		})
	}

	findings, err := m.analyzer.Observe(ctx, obs, snap.Time)
	if err != nil {
		return err
	}
	for _, f := range findings {
		m.report(ctx, f)
	}

	// Queue newly seen destinations for enrichment.
	for _, id := range m.store.takeNew() {
		select {
		case m.enrichQueue <- id:
		default:
			// The queue is full; enrichment is best-effort context, never a fact the
			// analysis depends on.
		}
	}
	return nil
}

func (m *destinationMonitor) report(ctx context.Context, f destinations.Finding) {
	o := f.Obs
	dest := ""
	if o.RemoteIP.IsValid() {
		dest = net.JoinHostPort(o.RemoteIP.String(), strconv.Itoa(o.RemotePort))
	}

	fields := events.Fields{}
	if dest != "" {
		fields = fields.Add("Destination", dest).
			Add("RemotePort", o.RemotePort).
			Add("Protocol", o.Protocol)
	}
	if o.Process != "" {
		fields = fields.Add("Process", o.Process)
		if o.PID > 0 {
			fields = fields.Add("PID", o.PID)
		}
	}
	for k, v := range f.Extra {
		fields = fields.Add(k, v)
	}
	fields = fields.Add("Confidence", f.Confidence).Add("Detail", f.Detail)

	// Attach whatever enrichment is already known, so the event is self-contained.
	if o.RemoteIP.IsValid() {
		if d, ok, err := m.a.db.DestinationByEndpoint(ctx, o.RemoteIP.String(), o.RemotePort, o.Protocol); err == nil && ok {
			if d.ReverseDNS != "" {
				fields = fields.Add("ReverseDNS", d.ReverseDNS)
			}
			if d.ASN != "" {
				fields = fields.Add("ASN", d.ASN)
			}
			if d.ASNOrg != "" {
				fields = fields.Add("Organization", d.ASNOrg)
			}
			if d.Country != "" {
				fields = fields.Add("Country", d.Country)
			}
			if !d.FirstSeen.IsZero() {
				fields = fields.Add("FirstSeen", d.FirstSeen)
			}
			if d.BytesSent > 0 {
				fields = fields.AddBytes("BytesSent", float64(d.BytesSent))
			}
		}
	}

	var ev events.Event
	switch f.Kind {
	case destinations.NewDestination:
		ev = events.New(events.NewExternalDestination)
	case destinations.HighVolumeNew:
		ev = events.New(events.NewHighVolumeDest)
	case destinations.RareDestination:
		ev = events.New(events.RareDestinationContact)
	case destinations.UnexpectedPort:
		ev = events.New(events.UnexpectedDestPort)
	case destinations.RapidFanout:
		ev = events.New(events.RapidDestinationFanout)
	default:
		return
	}
	m.a.log.Emit(ev.WithFields(fields).WithDestination(dest))
}

// enrich resolves reverse DNS and ASN details for queued destinations.
func (m *destinationMonitor) enrich(ctx context.Context) error {
	if !m.a.cfg.Destinations.Enabled {
		return nil
	}
	var enricher *publicip.Enricher
	if len(m.a.cfg.Destinations.Enrichment) > 0 || m.a.cfg.Destinations.EnrichmentURL != "" {
		enricher = publicip.NewEnricher(m.a.cfg.Destinations.EnrichmentURL, 5*time.Second)
	}

	// A bounded batch keeps the task well inside its timeout.
	const maxPerCycle = 20
	for i := 0; i < maxPerCycle; i++ {
		var req enrichRequest
		select {
		case req = <-m.enrichQueue:
		default:
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}

		var rdns, asn, org, country string
		if m.a.cfg.Destinations.ReverseDNS && m.a.cfg.Privacy.CollectRemoteHostnames {
			rdns = publicip.ReverseDNS(ctx, nil, req.addr, 2*time.Second)
		}
		if enricher != nil {
			if n, err := enricher.Lookup(ctx, req.addr); err == nil {
				asn, org, country = n.ASN, n.Org, n.Country
			}
		}
		if rdns == "" && asn == "" && org == "" && country == "" {
			continue
		}
		if err := m.a.db.SetDestinationEnrichment(ctx, req.id, rdns, asn, org, country); err != nil {
			return err
		}
	}
	return nil
}

// destinationStore adapts the database to the analyzer's Store interface.
type destinationStore struct {
	db *database.DB
	// newIDs collects destinations seen for the first time, for enrichment.
	newIDs []enrichRequest
}

func (s *destinationStore) Upsert(ctx context.Context, o destinations.Observation) (int64, bool, time.Time, int64, error) {
	dst := database.Destination{
		RemoteIP: o.RemoteIP.String(), RemotePort: o.RemotePort, Protocol: o.Protocol,
		FirstSeen: o.Time, LastSeen: o.Time, Contacts: 1,
		Internal: o.Internal,
	}
	// Socket queue depths are not cumulative byte totals, so they are not accumulated
	// as if they were; the destination row records contact counts and the connection
	// rows carry what byte information the platform does provide.
	if o.Process != "" {
		if b, err := json.Marshal([]string{o.Process}); err == nil {
			dst.Processes = string(b)
		}
	}

	id, isNew, err := s.db.UpsertDestination(ctx, dst)
	if err != nil {
		return 0, false, time.Time{}, 0, err
	}
	if isNew {
		s.newIDs = append(s.newIDs, enrichRequest{id: id, addr: o.RemoteIP})
		return id, true, o.Time, 1, nil
	}

	existing, ok, err := s.db.DestinationByEndpoint(ctx, dst.RemoteIP, dst.RemotePort, dst.Protocol)
	if err != nil || !ok {
		return id, false, time.Time{}, 0, err
	}
	return id, false, existing.FirstSeen, existing.Contacts, nil
}

func (s *destinationStore) ContactFrequencies(ctx context.Context) ([]float64, error) {
	return s.db.ContactFrequencies(ctx)
}

func (s *destinationStore) takeNew() []enrichRequest {
	out := s.newIDs
	s.newIDs = nil
	return out
}
