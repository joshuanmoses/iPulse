package agent

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/threatintel"
	"github.com/ipulse/ipulse/internal/util"
)

// threatMonitor imports locally-held threat intelligence and matches observed
// connections against it.
//
// A match is reported as evidence with its source and confidence attached. iPulse does
// not block traffic and does not describe a match as confirmed malicious activity: feeds
// carry false positives, indicators go stale, and the operator is the one who decides.
type threatMonitor struct {
	a        *Agent
	importer *threatintel.Importer
	matcher  *threatintel.Matcher
	// reported suppresses repeats for the same destination and indicator.
	reported map[string]time.Time
}

func newThreatMonitor(a *Agent) *threatMonitor {
	allowPrefixes, invalid := util.ParsePrefixes(a.cfg.ThreatIntel.AllowList)
	var allowDomains []string
	for _, entry := range invalid {
		// An entry that is not an address or prefix is treated as a domain, which is
		// what an operator listing their own hostname means.
		allowDomains = append(allowDomains, entry)
	}

	return &threatMonitor{
		a:        a,
		importer: threatintel.NewImporter(2*time.Minute, 256<<20, a.cfg.ThreatIntel.MaxIndicators),
		matcher: threatintel.NewMatcher(threatintel.MatcherConfig{
			AllowPrefixes: allowPrefixes,
			AllowDomains:  allowDomains,
			MatchPrivate:  a.cfg.ThreatIntel.MatchPrivate,
		}, &threatLookup{db: a.db}),
		reported: map[string]time.Time{},
	}
}

func (m *threatMonitor) Name() string { return "threat-intel" }

func (m *threatMonitor) Tasks() []Task {
	tasks := []Task{{
		Name:         "threat-feeds",
		Interval:     m.a.cfg.Monitoring.ThreatFeedInterval.D(),
		Timeout:      10 * time.Minute,
		InitialDelay: 30 * time.Second,
		RunOnStart:   true,
		Fn:           m.importFeeds,
	}}
	return tasks
}

// importFeeds refreshes every configured feed.
func (m *threatMonitor) importFeeds(ctx context.Context) error {
	feeds := m.a.cfg.ThreatIntel.Feeds
	if len(feeds) == 0 {
		// No feed is configured by default: iPulse contacts nobody unless asked to.
		return nil
	}

	statuses, _ := m.a.db.FeedStatuses(ctx)
	etags := map[string]string{}
	for _, s := range statuses {
		etags[s.Name] = s.ETag
	}

	imported := false
	for _, f := range feeds {
		if f.Enabled != nil && !*f.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if m.importOne(ctx, f, etags[f.Name]) {
			imported = true
		}
	}
	if imported {
		// New indicators mean cached "no match" answers may now be wrong.
		m.matcher.Invalidate()
	}
	return nil
}

// importOne imports a single feed and records the outcome, returning whether anything
// changed.
func (m *threatMonitor) importOne(ctx context.Context, f config.ThreatFeed, etag string) bool {
	start := time.Now()
	feed := threatintel.Feed{
		Name:       f.Name,
		URL:        f.URL,
		Path:       f.Path,
		Format:     threatintel.Format(strings.ToLower(f.Format)),
		Kind:       threatintel.Kind(strings.ToLower(f.Type)),
		Confidence: threatintel.ConfidenceOf(f.Confidence),
		Column:     f.Column,
		Field:      f.Field,
		ETag:       etag,
	}

	res, err := m.importer.Import(ctx, feed)
	status := database.FeedStatus{Name: f.Name, LastImport: time.Now(), ETag: res.ETag}
	if err != nil {
		status.LastError = err.Error()
		_ = m.a.db.SetFeedStatus(ctx, status)

		var lastSuccess string
		if statuses, serr := m.a.db.FeedStatuses(ctx); serr == nil {
			for _, s := range statuses {
				if s.Name == f.Name && !s.LastSuccess.IsZero() {
					lastSuccess = s.LastSuccess.Format(time.RFC3339)
				}
			}
		}
		m.a.log.Emit(events.New(events.ThreatFeedImportFailed).
			WithField("Source", f.Name).
			WithField("Format", f.Format).
			WithField("Error", err).
			WithField("LastSuccess", lastSuccess))
		return false
	}

	if res.NotModified {
		// Nothing to do, but the indicators must not expire just because the feed is
		// unchanged, so their last-seen timestamps are refreshed.
		status.LastSuccess = time.Now()
		_ = m.a.db.SetFeedStatus(ctx, status)
		return false
	}

	indicators := make([]database.Indicator, 0, len(res.Indicators))
	for _, ind := range res.Indicators {
		indicators = append(indicators, database.Indicator{
			Indicator:  ind.Value,
			Kind:       string(ind.Kind),
			Confidence: feed.Confidence,
			Note:       ind.Note,
		})
	}

	added, updated, err := m.a.db.UpsertIndicators(ctx, f.Name, indicators)
	if err != nil {
		status.LastError = err.Error()
		_ = m.a.db.SetFeedStatus(ctx, status)
		m.a.log.Emit(events.New(events.ThreatFeedImportFailed).
			WithField("Source", f.Name).
			WithField("Format", string(res.Format)).
			WithField("Error", err))
		return false
	}

	status.LastSuccess = time.Now()
	status.Indicators = int64(len(indicators))
	_ = m.a.db.SetFeedStatus(ctx, status)

	fields := events.Fields{}.
		Add("Source", f.Name).
		Add("Format", string(res.Format)).
		Add("Indicators", len(indicators)).
		Add("Added", added).
		Add("Updated", updated).
		AddDuration("Duration", time.Since(start)).
		Add("Confidence", feed.Confidence)
	if res.Skipped > 0 {
		fields = fields.Add("Unusable", res.Skipped)
	}
	if res.Truncated {
		fields = fields.Add("Truncated", true).
			Add("Limit", m.a.cfg.ThreatIntel.MaxIndicators)
	}
	if res.Bytes > 0 {
		fields = fields.AddBytes("Bytes", float64(res.Bytes))
	}
	m.a.log.Emit(events.New(events.ThreatFeedImported).WithFields(fields))
	return added > 0 || updated > 0
}

// threatLookup adapts the database to the matcher's Lookup interface.
type threatLookup struct{ db *database.DB }

func (l *threatLookup) MatchIP(ctx context.Context, addr netip.Addr) ([]threatintel.Match, error) {
	rows, err := l.db.MatchIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return convertIndicators(rows), nil
}

func (l *threatLookup) MatchDomain(ctx context.Context, domain string) ([]threatintel.Match, error) {
	rows, err := l.db.MatchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := convertIndicators(rows)
	for i := range out {
		out[i].Domain = domain
	}
	return out, nil
}

func convertIndicators(rows []database.Indicator) []threatintel.Match {
	out := make([]threatintel.Match, 0, len(rows))
	for _, r := range rows {
		out = append(out, threatintel.Match{
			Indicator: r.Indicator, Kind: threatintel.Kind(r.Kind), Source: r.Source,
			Confidence: r.Confidence, Note: r.Note,
		})
	}
	return out
}

// Connections implements connectionConsumer: every observed destination is checked.
func (m *threatMonitor) Connections(ctx context.Context, snap network.Snapshot) error {
	if !m.a.cfg.ThreatIntel.Enabled {
		return nil
	}
	for _, c := range snap.Connections {
		if ctx.Err() != nil {
			return nil
		}
		addr, err := netip.ParseAddr(c.RemoteIP)
		if err != nil {
			continue
		}
		matches, err := m.matcher.MatchAddr(ctx, addr)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			continue
		}
		best, _ := threatintel.Highest(matches)
		m.report(ctx, c, best, snap.Time)
	}
	return nil
}

// report records and logs a match.
func (m *threatMonitor) report(ctx context.Context, c database.Connection, match threatintel.Match, now time.Time) {
	key := c.RemoteIP + "|" + match.Indicator + "|" + match.Source
	if last, ok := m.reported[key]; ok && now.Sub(last) < m.a.cfg.Alerts.Cooldown.D() {
		return
	}
	m.reported[key] = now
	if len(m.reported) > 4096 {
		for k, at := range m.reported {
			if now.Sub(at) > 24*time.Hour {
				delete(m.reported, k)
			}
		}
	}

	dest := net.JoinHostPort(c.RemoteIP, strconv.Itoa(c.RemotePort))
	feedStatus, _ := m.a.db.FeedStatuses(ctx)
	feedUpdated := ""
	for _, s := range feedStatus {
		if s.Name == match.Source && !s.LastSuccess.IsZero() {
			feedUpdated = s.LastSuccess.Format(time.RFC3339)
		}
	}

	fields := events.Fields{}.
		Add("RemoteIP", c.RemoteIP).
		Add("RemotePort", c.RemotePort).
		Add("Protocol", c.Protocol).
		Add("ThreatSource", match.Source).
		Add("Indicator", match.Indicator).
		Add("IndicatorType", string(match.Kind)).
		Add("Confidence", strings.Title(match.Confidence))
	if feedUpdated != "" {
		fields = fields.Add("FeedUpdated", feedUpdated)
	}
	if match.Note != "" {
		fields = fields.Add("Note", match.Note)
	}
	if c.Process != "" {
		fields = fields.Add("Process", c.Process).Add("PID", c.PID)
	}
	if c.Exe != "" {
		fields = fields.Add("ExecutablePath", c.Exe)
	}
	if c.User != "" {
		fields = fields.Add("User", c.User)
	}
	if match.Domain != "" {
		fields = fields.Add("Domain", match.Domain)
	}

	// A high-confidence match gets the specific event; anything less is reported as a
	// threat-intelligence match, which is what it is.
	code := events.ThreatIntelligenceMatch
	if strings.EqualFold(match.Confidence, "high") {
		code = events.KnownMaliciousDest
	}
	if match.Kind == threatintel.KindDomain {
		code = events.MaliciousDomainConn
	}

	ev := events.New(code).WithFields(fields).WithDestination(dest)
	if c.Process != "" {
		ev = ev.WithProcess(c.Process, c.PID)
	}
	m.a.log.Emit(ev)

	if _, err := m.a.db.InsertThreatMatch(ctx, database.ThreatMatch{
		Time: now, Indicator: match.Indicator, Kind: string(match.Kind), Source: match.Source,
		Confidence: match.Confidence, RemoteIP: c.RemoteIP, RemotePort: c.RemotePort,
		Protocol: c.Protocol, Domain: match.Domain, PID: c.PID, Process: c.Process,
		Exe: c.Exe, User: c.User, BytesSent: c.BytesSent, BytesRecv: c.BytesRecv,
	}); err != nil {
		m.a.log.Emit(events.New(events.DatabaseError).
			WithField("Operation", "insert threat match").
			WithField("Error", err))
		return
	}

	// Flag the destination so the dashboard can highlight it.
	if d, ok, err := m.a.db.DestinationByEndpoint(ctx, c.RemoteIP, c.RemotePort, c.Protocol); err == nil && ok {
		_ = m.a.db.FlagDestination(ctx, d.ID)
	}
}
