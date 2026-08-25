// Package destinations maintains the history of remote endpoints this host contacts and
// reports what is new, rare or unexpected about them.
//
// The analysis is deliberately conservative. Most new destinations are entirely benign -
// a CDN node, an update server, a newly resolved address for a service already in use -
// so novelty on its own is reported at informational severity, and only the combination
// of novelty with volume, or contact with many destinations at once, is treated as
// something an operator should look at.
package destinations

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/util"
)

// Observation is one contact with a destination during a collection cycle.
type Observation struct {
	Time       time.Time
	RemoteIP   netip.Addr
	RemotePort int
	Protocol   string
	Process    string
	PID        int
	Exe        string
	User       string
	Internal   bool
	BytesSent  int64
	BytesRecv  int64
	State      string
}

// Key is the destination identity.
func (o Observation) Key() string {
	return strings.ToLower(o.Protocol) + "|" + o.RemoteIP.String() + "|" + itoa(o.RemotePort)
}

// Finding is something worth reporting about a destination.
type Finding struct {
	Kind   FindingKind
	Time   time.Time
	Obs    Observation
	Detail string
	// Confidence is low, medium or high, and is always reported so a reader knows how
	// much weight the finding carries.
	Confidence string
	// Extra carries finding-specific fields for the event body.
	Extra map[string]string
}

// FindingKind identifies what was found.
type FindingKind string

// Finding kinds.
const (
	NewDestination  FindingKind = "new-destination"
	RareDestination FindingKind = "rare-destination"
	UnexpectedPort  FindingKind = "unexpected-port"
	RapidFanout     FindingKind = "rapid-fanout"
	HighVolumeNew   FindingKind = "high-volume-new-destination"
)

// Config configures the analyzer.
type Config struct {
	// LearningPeriod suppresses novelty reporting entirely for this long after start,
	// while the normal picture is built. Without it, every destination is new on the
	// first day and the log is useless.
	LearningPeriod time.Duration
	// NewWindow is how long a destination counts as new.
	NewWindow time.Duration
	// RarePercentile marks destinations below this contact-frequency percentile as rare.
	RarePercentile float64
	// HighVolumeBytes is the outbound volume that makes a new destination notable.
	HighVolumeBytes int64
	// FanoutWindow and FanoutThreshold detect contact with many destinations at once.
	FanoutWindow    time.Duration
	FanoutThreshold int
	// ExpectedPorts are ports considered normal for outbound traffic.
	ExpectedPorts []int
	// ReportInternal includes private-range destinations in novelty reporting. Off by
	// default: lateral analysis covers internal traffic, and a busy LAN would otherwise
	// swamp the destination view.
	ReportInternal bool
}

// Store is the persistence the analyzer needs. It is an interface so the analysis can be
// tested without a database.
type Store interface {
	// Upsert records a contact and reports whether the destination was previously
	// unknown, along with its identifier.
	Upsert(ctx context.Context, obs Observation) (id int64, isNew bool, firstSeen time.Time, contacts int64, err error)
	// ContactFrequencies returns the contact counts of all known external destinations,
	// used to compute the rarity percentile.
	ContactFrequencies(ctx context.Context) ([]float64, error)
}

// Analyzer maintains destination history and produces findings.
type Analyzer struct {
	cfg   Config
	store Store
	start time.Time

	mu sync.Mutex
	// expectedPorts is the configured set, for fast lookup.
	expectedPorts map[int]bool
	// portProfile is the set of ports actually observed, so "unexpected" means unusual
	// for this host rather than unusual in general.
	portProfile map[int]int
	// recentContacts tracks distinct destinations per process for fanout detection.
	recentContacts map[string]*fanoutTracker
	// reported remembers what has already been reported, so the same new destination is
	// not reported on every cycle.
	reported map[string]time.Time
	// rarityThreshold is refreshed periodically from the stored frequencies.
	rarityThreshold float64
	rarityRefreshed time.Time
}

type fanoutTracker struct {
	contacts map[string]time.Time
	reported time.Time
}

// New creates an analyzer.
func New(cfg Config, store Store, start time.Time) *Analyzer {
	expected := make(map[int]bool, len(cfg.ExpectedPorts))
	for _, p := range cfg.ExpectedPorts {
		expected[p] = true
	}
	return &Analyzer{
		cfg:            cfg,
		store:          store,
		start:          start,
		expectedPorts:  expected,
		portProfile:    map[int]int{},
		recentContacts: map[string]*fanoutTracker{},
		reported:       map[string]time.Time{},
	}
}

// Learning reports whether the analyzer is still in its initial learning period.
func (a *Analyzer) Learning(now time.Time) bool {
	return now.Sub(a.start) < a.cfg.LearningPeriod
}

// Observe records a batch of observations and returns the findings.
func (a *Analyzer) Observe(ctx context.Context, obs []Observation, now time.Time) ([]Finding, error) {
	var findings []Finding
	learning := a.Learning(now)

	a.refreshRarity(ctx, now)

	for _, o := range obs {
		if !o.RemoteIP.IsValid() {
			continue
		}
		if o.Internal && !a.cfg.ReportInternal {
			// Internal traffic is the lateral detector's business.
			continue
		}
		id, isNew, firstSeen, contacts, err := a.store.Upsert(ctx, o)
		if err != nil {
			return findings, err
		}
		_ = id

		a.recordPort(o.RemotePort)
		a.recordFanout(o, now)

		if learning {
			// History is still being built; recording continues, reporting does not.
			continue
		}

		recentlyNew := !firstSeen.IsZero() && now.Sub(firstSeen) <= a.cfg.NewWindow
		if isNew && a.shouldReport(o.Key(), now, a.cfg.NewWindow) {
			findings = append(findings, Finding{
				Kind: NewDestination, Time: now, Obs: o, Confidence: "low",
				Detail: "first contact with this destination",
			})
		}

		// New plus significant outbound volume is the combination worth attention.
		if recentlyNew && a.cfg.HighVolumeBytes > 0 && o.BytesSent >= a.cfg.HighVolumeBytes &&
			a.shouldReport("volume:"+o.Key(), now, a.cfg.NewWindow) {
			findings = append(findings, Finding{
				Kind: HighVolumeNew, Time: now, Obs: o, Confidence: "medium",
				Detail: "a destination first seen recently is receiving significant outbound traffic",
				Extra:  map[string]string{"FirstSeen": firstSeen.Format(time.RFC3339)},
			})
		}

		if !isNew && a.isRare(float64(contacts)) && a.shouldReport("rare:"+o.Key(), now, 24*time.Hour) {
			findings = append(findings, Finding{
				Kind: RareDestination, Time: now, Obs: o, Confidence: "low",
				Detail: "this destination is contacted very rarely",
				Extra: map[string]string{
					"Frequency": itoa64(contacts),
					"FirstSeen": firstSeen.Format(time.RFC3339),
				},
			})
		}

		if a.isUnexpectedPort(o.RemotePort) && a.shouldReport("port:"+o.Key(), now, 6*time.Hour) {
			findings = append(findings, Finding{
				Kind: UnexpectedPort, Time: now, Obs: o, Confidence: "low",
				Detail: "outbound connection to a port outside the learned profile",
				Extra:  map[string]string{"PortProfile": a.describePortProfile()},
			})
		}
	}

	findings = append(findings, a.checkFanout(now)...)
	a.prune(now)
	return findings, nil
}

// recordPort adds to the learned port profile.
func (a *Analyzer) recordPort(port int) {
	if port <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.portProfile[port]++
}

// isUnexpectedPort reports whether a port is outside both the configured set and the
// learned profile. A port becomes normal for this host once it has been seen enough
// times, which is what stops a site's own application from being reported forever.
func (a *Analyzer) isUnexpectedPort(port int) bool {
	if port <= 0 || a.expectedPorts[port] {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	const familiarAfter = 5
	return a.portProfile[port] < familiarAfter
}

func (a *Analyzer) describePortProfile() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	type entry struct {
		port, count int
	}
	list := make([]entry, 0, len(a.portProfile))
	for p, c := range a.portProfile {
		list = append(list, entry{p, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
	if len(list) > 8 {
		list = list[:8]
	}
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, itoa(e.port))
	}
	return strings.Join(parts, ",")
}

// recordFanout tracks distinct destinations per process within the fanout window.
func (a *Analyzer) recordFanout(o Observation, now time.Time) {
	proc := o.Process
	if proc == "" {
		proc = "(unattributed)"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.recentContacts[proc]
	if !ok {
		t = &fanoutTracker{contacts: map[string]time.Time{}}
		a.recentContacts[proc] = t
	}
	t.contacts[o.RemoteIP.String()] = now
}

// checkFanout reports processes contacting an unusual number of distinct destinations.
func (a *Analyzer) checkFanout(now time.Time) []Finding {
	if a.cfg.FanoutThreshold <= 0 || a.Learning(now) {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var findings []Finding
	cutoff := now.Add(-a.cfg.FanoutWindow)
	for proc, t := range a.recentContacts {
		for addr, seen := range t.contacts {
			if seen.Before(cutoff) {
				delete(t.contacts, addr)
			}
		}
		if len(t.contacts) < a.cfg.FanoutThreshold {
			continue
		}
		// One report per window per process.
		if !t.reported.IsZero() && now.Sub(t.reported) < a.cfg.FanoutWindow {
			continue
		}
		t.reported = now
		findings = append(findings, Finding{
			Kind: RapidFanout, Time: now, Confidence: "low",
			Obs:    Observation{Process: proc, Time: now},
			Detail: "many distinct external destinations contacted in a short window",
			Extra: map[string]string{
				"DistinctDestinations": itoa(len(t.contacts)),
				"Window":               a.cfg.FanoutWindow.String(),
			},
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Obs.Process < findings[j].Obs.Process })
	return findings
}

// refreshRarity recomputes the contact-frequency percentile that defines "rare".
func (a *Analyzer) refreshRarity(ctx context.Context, now time.Time) {
	a.mu.Lock()
	needsRefresh := now.Sub(a.rarityRefreshed) > 15*time.Minute
	a.mu.Unlock()
	if !needsRefresh || a.cfg.RarePercentile <= 0 {
		return
	}
	freqs, err := a.store.ContactFrequencies(ctx)
	if err != nil || len(freqs) < 20 {
		// Too little history for a percentile to mean anything.
		a.mu.Lock()
		a.rarityThreshold = 0
		a.rarityRefreshed = now
		a.mu.Unlock()
		return
	}
	threshold := util.Percentile(freqs, a.cfg.RarePercentile)
	a.mu.Lock()
	a.rarityThreshold = threshold
	a.rarityRefreshed = now
	a.mu.Unlock()
}

func (a *Analyzer) isRare(contacts float64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rarityThreshold > 0 && contacts <= a.rarityThreshold
}

// shouldReport enforces one report per key per interval.
func (a *Analyzer) shouldReport(key string, now time.Time, interval time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.reported[key]
	if ok && now.Sub(last) < interval {
		return false
	}
	a.reported[key] = now
	return true
}

// prune bounds memory: report memos and fanout trackers are dropped once they can no
// longer affect a decision.
func (a *Analyzer) prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-24 * time.Hour)
	for key, at := range a.reported {
		if at.Before(cutoff) {
			delete(a.reported, key)
		}
	}
	fanoutCutoff := now.Add(-2 * a.cfg.FanoutWindow)
	for proc, t := range a.recentContacts {
		if len(t.contacts) == 0 && t.reported.Before(fanoutCutoff) {
			delete(a.recentContacts, proc)
		}
	}
	if len(a.portProfile) > 4096 {
		// A host talking to thousands of distinct ports has no useful profile; reset
		// rather than grow without bound.
		a.portProfile = map[int]int{}
	}
}

// Stats reports analyzer state, for diagnostics.
type Stats struct {
	KnownPorts       int     `json:"known_ports"`
	TrackedProcesses int     `json:"tracked_processes"`
	RarityThreshold  float64 `json:"rarity_threshold"`
	Learning         bool    `json:"learning"`
}

// Stats returns a snapshot of internal state.
func (a *Analyzer) Stats(now time.Time) Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Stats{
		KnownPorts:       len(a.portProfile),
		TrackedProcesses: len(a.recentContacts),
		RarityThreshold:  a.rarityThreshold,
		Learning:         now.Sub(a.start) < a.cfg.LearningPeriod,
	}
}

func itoa(v int) string { return itoa64(int64(v)) }

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [21]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
