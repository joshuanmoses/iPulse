// Package api serves the iPulse local REST API and the embedded web dashboard.
//
// Security posture: bound to loopback by default, an optional bearer token, a Host
// header allow-list that defeats DNS rebinding, request size caps, read/write timeouts,
// rate limiting on the endpoints that start real network tests, and no CORS.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/logging"
	"github.com/ipulse/ipulse/internal/platform"
)

// Backend is the part of the agent the API needs. Declaring it as an interface keeps the
// dependency one-way: the agent never imports the API.
type Backend interface {
	State() *agent.State
	Config() *config.Config
	DB() *database.DB
	Scheduler() *agent.Scheduler
	Capabilities() platform.Capabilities
}

// Options configures the server.
type Options struct {
	Config  *config.Config
	Backend Backend
	Logger  *logging.Logger
}

// Server is the local HTTP server.
type Server struct {
	cfg     *config.Config
	backend Backend
	log     *logging.Logger

	srv      *http.Server
	listener net.Listener
	addr     string

	limiter *rateLimiter

	mu       sync.Mutex
	requests int64
	started  time.Time
	closed   bool
}

// New builds the server and its routes.
func New(opts Options) (*Server, error) {
	if opts.Config == nil || opts.Backend == nil {
		return nil, errors.New("api: configuration and backend are required")
	}
	log := opts.Logger
	if log == nil {
		log = logging.Discard()
	}
	s := &Server{
		cfg:     opts.Config,
		backend: opts.Backend,
		log:     log,
		limiter: newRateLimiter(opts.Config.Dashboard.RateLimitPerMinute, time.Minute),
		addr:    net.JoinHostPort(opts.Config.Dashboard.Address, fmt.Sprint(opts.Config.Dashboard.Port)),
	}
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       opts.Config.Dashboard.ReadTimeout.D(),
		WriteTimeout:      opts.Config.Dashboard.WriteTimeout.D(),
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	return s, nil
}

// Addr returns the listen address.
func (s *Server) Addr() string { return s.addr }

// Start binds the listener and serves in the background.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", s.addr, err)
	}
	s.listener = ln
	s.started = time.Now()

	go func() {
		var err error
		if s.cfg.Dashboard.TLSCertFile != "" {
			err = s.srv.ServeTLS(ln, s.cfg.Dashboard.TLSCertFile, s.cfg.Dashboard.TLSKeyFile)
		} else {
			err = s.srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Emit(events.New(events.APIStopped).WithSeverity(events.Error).
				WithField("Reason", err.Error()))
		}
	}()
	return nil
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.srv.Shutdown(ctx)
}

// authorized enforces the Host allow-list and the optional bearer token.
//
// The Host check is what makes a loopback-bound API safe against DNS rebinding: a page
// on the public Internet can resolve a name to 127.0.0.1, but it cannot make the browser
// send a Host header that is on this list.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	allowed := false
	for _, h := range s.cfg.Dashboard.AllowedHosts {
		candidate := strings.Trim(h, "[]")
		if strings.EqualFold(candidate, host) {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "host_not_allowed",
			"the Host header is not in dashboard.allowed_hosts")
		return false
	}

	if token := s.cfg.Dashboard.AuthToken; token != "" {
		provided := r.Header.Get("X-iPulse-Token")
		if provided == "" {
			if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
				provided = strings.TrimPrefix(v, "Bearer ")
			}
		}
		// Constant-time comparison: a timing side channel on a local token is a small
		// risk, but there is no reason to accept it.
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="iPulse"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid API token is required")
			return false
		}
	}
	return true
}

// isLocalRequest reports whether the peer is on this host, used to gate the endpoints
// that start real network tests.
func isLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// rateLimiter is a small fixed-window limiter keyed by client address.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if limit <= 0 {
		limit = 10
	}
	return &rateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// allow reports whether the key may proceed, and how long to wait if not.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)

	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		return false, kept[0].Add(l.window).Sub(now)
	}
	kept = append(kept, now)
	l.hits[key] = kept

	// Bound the map so a long-lived agent cannot accumulate keys without limit.
	if len(l.hits) > 1024 {
		for k, v := range l.hits {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.hits, k)
			}
		}
	}
	return true, 0
}
