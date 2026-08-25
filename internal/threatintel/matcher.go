package threatintel

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/util"
)

// Match is one connection matching local threat intelligence.
type Match struct {
	Indicator  string
	Kind       Kind
	Source     string
	Confidence string
	Note       string
	// Domain is set when the match was on a name rather than an address.
	Domain string
}

// Lookup is the store interface the matcher needs, so matching can be tested without a
// database.
type Lookup interface {
	MatchIP(ctx context.Context, addr netip.Addr) ([]Match, error)
	MatchDomain(ctx context.Context, domain string) ([]Match, error)
}

// MatcherConfig configures matching.
type MatcherConfig struct {
	// AllowList holds prefixes and domains that are never reported, for a site's own
	// infrastructure appearing in a public feed.
	AllowPrefixes []netip.Prefix
	AllowDomains  []string
	// MatchPrivate also checks private addresses. Off by default: a feed listing an
	// RFC 1918 address would otherwise match half the local network.
	MatchPrivate bool
	// CacheTTL is how long a lookup result is reused. Connection tables repeat the same
	// destinations every cycle, so caching removes almost all of the query load.
	CacheTTL time.Duration
	// NegativeCacheTTL is how long a "no match" answer is reused.
	NegativeCacheTTL time.Duration
}

// Matcher checks addresses and domains against the local store.
type Matcher struct {
	cfg    MatcherConfig
	lookup Lookup

	mu    sync.Mutex
	cache map[string]cacheEntry
	// stats are exposed for diagnostics.
	hits, misses, cached, allowed int64
}

type cacheEntry struct {
	matches []Match
	expires time.Time
}

// NewMatcher creates a matcher.
func NewMatcher(cfg MatcherConfig, lookup Lookup) *Matcher {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Minute
	}
	if cfg.NegativeCacheTTL <= 0 {
		cfg.NegativeCacheTTL = 5 * time.Minute
	}
	return &Matcher{cfg: cfg, lookup: lookup, cache: map[string]cacheEntry{}}
}

// MatchAddr checks one address.
func (m *Matcher) MatchAddr(ctx context.Context, addr netip.Addr) ([]Match, error) {
	if !addr.IsValid() {
		return nil, nil
	}
	if !m.cfg.MatchPrivate && util.IsPrivateAddr(addr) {
		return nil, nil
	}
	if util.MatchesAnyPrefix(addr, m.cfg.AllowPrefixes) {
		m.count(&m.allowed)
		return nil, nil
	}

	key := "ip:" + addr.String()
	if cached, ok := m.fromCache(key); ok {
		return cached, nil
	}
	matches, err := m.lookup.MatchIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	m.store(key, matches)
	return matches, nil
}

// MatchDomain checks one name, including its parent domains.
func (m *Matcher) MatchDomain(ctx context.Context, domain string) ([]Match, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, nil
	}
	for _, allowed := range m.cfg.AllowDomains {
		allowed = strings.ToLower(strings.TrimSuffix(allowed, "."))
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			m.count(&m.allowed)
			return nil, nil
		}
	}

	key := "domain:" + domain
	if cached, ok := m.fromCache(key); ok {
		return cached, nil
	}
	matches, err := m.lookup.MatchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	m.store(key, matches)
	return matches, nil
}

func (m *Matcher) fromCache(key string) ([]Match, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	m.cached++
	return entry.matches, true
}

func (m *Matcher) store(key string, matches []Match) {
	ttl := m.cfg.NegativeCacheTTL
	if len(matches) > 0 {
		ttl = m.cfg.CacheTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(matches) > 0 {
		m.hits++
	} else {
		m.misses++
	}
	m.cache[key] = cacheEntry{matches: matches, expires: time.Now().Add(ttl)}

	// Bound the cache: a host talking to very many destinations must not accumulate
	// entries without limit.
	if len(m.cache) > 8192 {
		now := time.Now()
		for k, e := range m.cache {
			if now.After(e.expires) {
				delete(m.cache, k)
			}
		}
		// Still too large: clear it rather than grow.
		if len(m.cache) > 8192 {
			m.cache = map[string]cacheEntry{}
		}
	}
}

func (m *Matcher) count(counter *int64) {
	m.mu.Lock()
	*counter++
	m.mu.Unlock()
}

// Stats reports matcher counters.
type Stats struct {
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
	Cached  int64 `json:"cached"`
	Allowed int64 `json:"allow_listed"`
	Entries int   `json:"cache_entries"`
}

// Stats returns a snapshot of the counters.
func (m *Matcher) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{Hits: m.hits, Misses: m.misses, Cached: m.cached, Allowed: m.allowed, Entries: len(m.cache)}
}

// Invalidate clears the cache, which is needed after a feed import changes the store.
func (m *Matcher) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = map[string]cacheEntry{}
}

// Highest returns the match with the greatest confidence, which is the one worth
// reporting when several feeds list the same destination.
func Highest(matches []Match) (Match, bool) {
	if len(matches) == 0 {
		return Match{}, false
	}
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	best := matches[0]
	for _, m := range matches[1:] {
		if rank[strings.ToLower(m.Confidence)] > rank[strings.ToLower(best.Confidence)] {
			best = m
		}
	}
	return best, true
}
