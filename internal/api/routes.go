package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxRequestBody caps request bodies. Nothing the API accepts is large, so a small cap
// removes a whole class of resource-exhaustion problems.
const maxRequestBody = 64 << 10

// APIPrefix is the versioned API root.
const APIPrefix = "/api/v1/"

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Read endpoints.
	get := func(path string, h http.HandlerFunc) {
		mux.Handle(APIPrefix+path, s.wrap(http.MethodGet, h))
	}
	post := func(path string, h http.HandlerFunc) {
		mux.Handle(APIPrefix+path, s.wrap(http.MethodPost, h))
	}

	get("status", s.handleStatus)
	get("health", s.handleHealth)
	get("speed", s.handleSpeed)
	get("speed/history", s.handleSpeedHistory)
	get("events", s.handleEvents)
	get("events/catalog", s.handleEventCatalog)
	get("outages", s.handleOutages)
	get("connections", s.handleConnections)
	get("destinations", s.handleDestinations)
	get("interfaces", s.handleInterfaces)
	get("public-ip", s.handlePublicIP)
	get("config", s.handleConfig)
	get("measurements", s.handleMeasurements)
	get("traffic", s.handleTraffic)
	get("threats", s.handleThreats)
	get("routes", s.handleRoutes)
	get("tasks", s.handleTasks)
	get("privileges", s.handlePrivileges)
	get("summary", s.handleSummary)
	get("baselines", s.handleBaselines)

	// Test endpoints: these start real network activity, so they are rate limited and
	// (by default) restricted to loopback clients.
	post("tests/speed", s.testHandler("speedtest-manual", "speed"))
	post("tests/connectivity", s.testHandler("connectivity", "connectivity"))
	post("tests/dns", s.testHandler("dns", "dns"))
	post("tests/latency", s.testHandler("latency", "latency"))
	post("tests/traceroute", s.testHandler("route", "traceroute"))
	post("tests/public-ip", s.testHandler("public-ip", "public-ip"))
	post("diagnostics", s.testHandler("diagnostics", "diagnostics"))

	// Anything else under the API prefix is a 404 in JSON. Without this the subtree
	// falls through to the dashboard handler, and a script with a typo in the path
	// receives an HTML page with a 200 instead of an error it can act on.
	// Any method, because a POST to a path that does not exist is a missing endpoint,
	// not a wrong method, and answering 405 there sends the caller looking for a verb
	// that was never the problem.
	mux.HandleFunc(APIPrefix, s.handleUnknownAPI)
	mux.HandleFunc("/api/", s.handleUnknownAPI)

	// Dashboard: everything not under the API prefix.
	mux.Handle("/", s.staticHandler())
	return s.baseMiddleware(mux)
}

// baseMiddleware applies the protections that must cover every route, including the
// static dashboard.
func (s *Server) baseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.requests, 1)

		// Defence in depth for a page that is only ever meant to be viewed locally.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		// The dashboard is entirely self-contained: no external origin is needed, so
		// the policy forbids all of them.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		// No CORS headers are emitted at all, so a browser will not let another origin
		// read API responses.
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !s.authorized(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// wrap enforces the method for one API route and validates the parameters every route
// shares.
func (s *Server) wrap(method string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				"this endpoint accepts "+method)
			return
		}
		if code, msg, ok := validateCommonParams(r); !ok {
			writeError(w, http.StatusBadRequest, code, msg)
			return
		}
		h(w, r)
	})
}

// handleUnknownAPI answers any unmatched path under the API prefix.
func (s *Server) handleUnknownAPI(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "unknown_endpoint",
		fmt.Sprintf("no such endpoint: %s (see %sevents/catalog and the documentation for the endpoint list)",
			r.URL.Path, APIPrefix))
}

// validateCommonParams rejects malformed time windows and numbers rather than quietly
// substituting a default. A caller that asks for "1hour" and silently receives a
// different window than it asked for has no way to notice the mistake.
func validateCommonParams(r *http.Request) (code, message string, ok bool) {
	q := r.URL.Query()
	for _, name := range []string{"since", "until", "new_since"} {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, raw); err == nil {
			continue
		}
		if _, err := parseWindow(raw); err != nil {
			// The parser's own error names a partially-trimmed suffix, which reads as
			// nonsense to a caller; the message says what is accepted instead.
			return "bad_" + name, fmt.Sprintf(
				"invalid %s %q: use a window such as 30m, 6h, 7d, 2w, 3mo or 1y (m is minutes, mo is months), or an RFC 3339 timestamp",
				name, raw), false
		}
	}
	for _, name := range []string{"limit", "offset", "bucket_seconds"} {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		if _, err := strconv.Atoi(raw); err != nil {
			return "bad_" + name, fmt.Sprintf("invalid %s %q: expected a whole number", name, raw), false
		}
	}
	return "", "", true
}

// writeJSON emits a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// errorResponse is the uniform error shape.
type errorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: http.StatusText(status), Code: code, Message: message})
}

// --- query parameter helpers -------------------------------------------------

func queryInt(r *http.Request, name string, def, min, max int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// querySince parses a relative window ("24h", "7d") or an absolute RFC 3339 timestamp.
// Relative windows are what a dashboard needs; absolute ones are what a script needs.
//
// A malformed value has already been rejected with a 400 by validateCommonParams, so the
// default here is only ever used for a parameter that was not supplied.
func querySince(r *http.Request, name string, def time.Duration) time.Time {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return time.Now().Add(-def)
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if d, err := parseWindow(raw); err == nil {
		return time.Now().Add(-d)
	}
	return time.Now().Add(-def)
}

// parseWindow accepts Go durations plus the day, week, month and year suffixes an
// operator expects.
//
// The suffixes are checked longest-first, and "m" is deliberately left to Go's parser as
// minutes rather than claimed for months: "30m" means half an hour to everyone who types
// it, and reading it as thirty months would turn a small dashboard query into a scan of
// years of history. Months are written "mo".
func parseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty window")
	}
	suffixes := []struct {
		suffix string
		mult   time.Duration
	}{
		{"mo", 30 * 24 * time.Hour},
		{"d", 24 * time.Hour},
		{"w", 7 * 24 * time.Hour},
		{"y", 365 * 24 * time.Hour},
	}
	for _, sfx := range suffixes {
		if !strings.HasSuffix(s, sfx.suffix) {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, sfx.suffix), 64)
		if err != nil {
			return 0, err
		}
		if n <= 0 {
			return 0, fmt.Errorf("window must be positive")
		}
		return time.Duration(n * float64(sfx.mult)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	// A negative or zero window would silently select nothing.
	if d <= 0 {
		return 0, fmt.Errorf("window must be positive")
	}
	return d, nil
}

// clientKey identifies a client for rate limiting.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
