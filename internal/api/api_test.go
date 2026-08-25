package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/platform"
)

// stubBackend serves the API from a real database and a synthetic state, so the handlers
// are tested without starting an agent.
type stubBackend struct {
	cfg   *config.Config
	db    *database.DB
	state *agent.State
	sched *agent.Scheduler
}

func (s *stubBackend) State() *agent.State         { return s.state }
func (s *stubBackend) Config() *config.Config      { return s.cfg }
func (s *stubBackend) DB() *database.DB            { return s.db }
func (s *stubBackend) Scheduler() *agent.Scheduler { return s.sched }
func (s *stubBackend) Capabilities() platform.Capabilities {
	return platform.Capabilities{Platform: "test"}
}

func newTestServer(t *testing.T, tune func(*config.Config)) (*Server, *stubBackend) {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.Service.DataDir = dir
	cfg.Service.LogDir = dir
	cfg.Database.Path = filepath.Join(dir, "ipulse.db")
	if tune != nil {
		tune(&cfg)
	}
	cfg.ResolvedPaths()
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration invalid: %v", err)
	}

	db, err := database.Open(database.Options{Path: cfg.Database.Path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	backend := &stubBackend{
		cfg:   &cfg,
		db:    db,
		state: agent.NewState("test", "test/amd64", platform.Capabilities{Platform: "test"}),
		sched: agent.NewScheduler(nil),
	}
	srv, err := New(Options{Config: &cfg, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	return srv, backend
}

// do issues a request against the server's routes with a valid Host header.
func do(t *testing.T, srv *Server, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "127.0.0.1:8750"
	req.RemoteAddr = "127.0.0.1:54321"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, truncateBody(rec.Body.String()))
	}
	return out
}

func truncateBody(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// TestEveryDocumentedEndpointResponds covers the endpoint list in the requirements.
func TestEveryDocumentedEndpointResponds(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	for _, path := range []string{
		"status", "health", "speed", "speed/history", "events", "events/catalog",
		"outages", "connections", "destinations", "interfaces", "public-ip", "config",
		"measurements?metric=latency_ms", "traffic", "threats", "routes", "tasks",
		"privileges", "summary", "baselines",
	} {
		rec := do(t, srv, http.MethodGet, APIPrefix+path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d: %s", path, rec.Code, truncateBody(rec.Body.String()))
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("GET %s content type = %q", path, ct)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	rec := do(t, srv, http.MethodGet, APIPrefix+"status", nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP is missing %q: %s", directive, csp)
		}
	}
	// No CORS header may be emitted: another origin must not be able to read the API.
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("the API must not emit CORS headers")
	}
}

// TestHostAllowListDefeatsDNSRebinding is the protection that makes a loopback-bound API
// safe: a page on the public Internet can point a name at 127.0.0.1, but it cannot forge
// the Host header.
func TestHostAllowListDefeatsDNSRebinding(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, APIPrefix+"status", nil)
	req.Host = "attacker.example.com"
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a foreign Host header returned %d, want 403", rec.Code)
	}
	body := decode(t, rec)
	if body["code"] != "host_not_allowed" {
		t.Errorf("error code = %v", body["code"])
	}

	for _, host := range []string{"127.0.0.1:8750", "localhost:8750", "127.0.0.1"} {
		req := httptest.NewRequest(http.MethodGet, APIPrefix+"status", nil)
		req.Host = host
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q returned %d", host, rec.Code)
		}
	}
}

func TestAuthTokenIsEnforced(t *testing.T) {
	const token = "0123456789abcdef0123"
	srv, _ := newTestServer(t, func(c *config.Config) { c.Dashboard.AuthToken = token })

	if rec := do(t, srv, http.MethodGet, APIPrefix+"status", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a request with no token returned %d, want 401", rec.Code)
	}
	if rec := do(t, srv, http.MethodGet, APIPrefix+"status",
		map[string]string{"X-iPulse-Token": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a wrong token returned %d, want 401", rec.Code)
	}
	if rec := do(t, srv, http.MethodGet, APIPrefix+"status",
		map[string]string{"X-iPulse-Token": token}); rec.Code != http.StatusOK {
		t.Errorf("the correct token returned %d", rec.Code)
	}
	if rec := do(t, srv, http.MethodGet, APIPrefix+"status",
		map[string]string{"Authorization": "Bearer " + token}); rec.Code != http.StatusOK {
		t.Errorf("a bearer token returned %d", rec.Code)
	}
}

func TestMethodEnforcement(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	rec := do(t, srv, http.MethodPost, APIPrefix+"status", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to a read endpoint returned %d", rec.Code)
	}
	if rec.Header().Get("Allow") != http.MethodGet {
		t.Errorf("Allow header = %q", rec.Header().Get("Allow"))
	}
	if rec := do(t, srv, http.MethodGet, APIPrefix+"tests/speed", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on a test endpoint returned %d", rec.Code)
	}
}

// TestConfigEndpointRedactsSecrets keeps the token out of a response that a browser
// extension or a screenshot could expose.
func TestConfigEndpointRedactsSecrets(t *testing.T) {
	const token = "supersecrettoken1234"
	srv, _ := newTestServer(t, func(c *config.Config) { c.Dashboard.AuthToken = token })
	rec := do(t, srv, http.MethodGet, APIPrefix+"config",
		map[string]string{"X-iPulse-Token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), token) {
		t.Error("the configuration endpoint leaked the auth token")
	}
	if !strings.Contains(rec.Body.String(), "redacted") {
		t.Error("expected the token to be shown as redacted")
	}
}

func TestEventFilteringThroughTheAPI(t *testing.T) {
	srv, backend := newTestServer(t, nil)
	ctx := context.Background()
	now := time.Now()

	for _, ev := range []events.Event{
		events.New(events.SpeedTestCompleted).WithTime(now.Add(-time.Minute)).WithField("Status", "HEALTHY"),
		events.New(events.LatencyDegradation).WithTime(now.Add(-time.Minute)),
		events.New(events.ThreatIntelligenceMatch).WithTime(now.Add(-time.Minute)).
			WithProcess("example.bin", 42).WithDestination("203.0.113.20:443"),
	} {
		if _, err := backend.db.InsertEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		query string
		want  int
	}{
		{"events?since=1h", 3},
		{"events?since=1h&severity=warning", 2},
		{"events?since=1h&severity=info", 3},
		{"events?since=1h&code=1002", 1},
		{"events?since=1h&category=SECURITY", 1},
		{"events?since=1h&process=example", 1},
		{"events?since=1h&destination=203.0.113.20", 1},
		{"events?since=1h&q=HEALTHY", 1},
		{"events?since=1h&q=nothing-matches-this", 0},
	}
	for _, c := range cases {
		rec := do(t, srv, http.MethodGet, APIPrefix+c.query, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s returned %d", c.query, rec.Code)
			continue
		}
		body := decode(t, rec)
		list, _ := body["events"].([]any)
		if len(list) != c.want {
			t.Errorf("%s returned %d events, want %d", c.query, len(list), c.want)
		}
	}
}

func TestEventSeverityValidation(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	rec := do(t, srv, http.MethodGet, APIPrefix+"events?severity=bogus", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an invalid severity returned %d, want 400", rec.Code)
	}
	rec = do(t, srv, http.MethodGet, APIPrefix+"events?code=notanumber", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an invalid code returned %d, want 400", rec.Code)
	}
}

func TestMeasurementsRequireAMetric(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	if rec := do(t, srv, http.MethodGet, APIPrefix+"measurements", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a missing metric returned %d, want 400", rec.Code)
	}
}

func TestHealthEndpointPublishesItsFormula(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	body := decode(t, do(t, srv, http.MethodGet, APIPrefix+"health", nil))
	scoring, _ := body["scoring"].(string)
	if !strings.Contains(scoring, "weight") {
		t.Errorf("the health endpoint must document how the score is computed: %q", scoring)
	}
	if _, ok := body["weights"]; !ok {
		t.Error("the health endpoint must publish the weights")
	}
}

// TestTestEndpointsAreRateLimited protects the endpoints that start real network
// activity from being used as an amplifier.
func TestTestEndpointsAreRateLimited(t *testing.T) {
	srv, _ := newTestServer(t, func(c *config.Config) { c.Dashboard.RateLimitPerMinute = 2 })

	codes := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		codes = append(codes, do(t, srv, http.MethodPost, APIPrefix+"tests/dns", nil).Code)
	}
	// The task is not registered in this stub, so the permitted calls return 404; what
	// matters is that the limiter starts refusing.
	if codes[3] != http.StatusTooManyRequests {
		t.Errorf("the fourth request returned %d, want 429 (all: %v)", codes[3], codes)
	}
}

func TestRemoteTestsAreRefusedByDefault(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, APIPrefix+"tests/dns", nil)
	req.Host = "127.0.0.1:8750"
	req.RemoteAddr = "192.168.1.50:40000" // not loopback
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a remote test request returned %d, want 403", rec.Code)
	}
	if body := decode(t, rec); body["code"] != "remote_tests_disabled" {
		t.Errorf("error code = %v", body["code"])
	}
}

func TestDashboardIsServed(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	rec := do(t, srv, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the dashboard root returned %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>iPulse</title>") {
		t.Error("the dashboard shell was not served")
	}
	if rec := do(t, srv, http.MethodGet, "/overview", nil); rec.Code != http.StatusOK {
		t.Errorf("an application route returned %d", rec.Code)
	}
	if rec := do(t, srv, http.MethodGet, "/nope.js", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a missing asset returned %d", rec.Code)
	}
	for path, wantType := range map[string]string{"/app.js": "javascript", "/style.css": "css"} {
		rec := do(t, srv, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s returned %d", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Header().Get("Content-Type"), wantType) {
			t.Errorf("%s content type = %q", path, rec.Header().Get("Content-Type"))
		}
	}
}

// TestDashboardTraversalIsHarmless proves the embedded file system cannot be escaped.
func TestDashboardTraversalIsHarmless(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	for _, path := range []string{"/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/./../../go.mod"} {
		rec := do(t, srv, http.MethodGet, path, nil)
		if strings.Contains(rec.Body.String(), "root:") || strings.Contains(rec.Body.String(), "module ") {
			t.Errorf("%s escaped the embedded assets", path)
		}
	}
}

func TestDashboardCanBeDisabled(t *testing.T) {
	srv, _ := newTestServer(t, func(c *config.Config) { c.Dashboard.Enabled = false })
	if rec := do(t, srv, http.MethodGet, "/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a disabled dashboard returned %d, want 404", rec.Code)
	}
	// The API keeps working: an operator may want the API without the page.
	if rec := do(t, srv, http.MethodGet, APIPrefix+"status", nil); rec.Code != http.StatusOK {
		t.Errorf("the API returned %d with the dashboard disabled", rec.Code)
	}
}

func TestWindowParsing(t *testing.T) {
	cases := map[string]time.Duration{
		"30m": 30 * time.Minute,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"2w":  14 * 24 * time.Hour,
		"1y":  365 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseWindow(in)
		if err != nil || got != want {
			t.Errorf("parseWindow(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5h", "0d"} {
		if _, err := parseWindow(bad); err == nil {
			t.Errorf("parseWindow(%q) should fail", bad)
		}
	}
}

func TestQueryIntClamping(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?limit=99999&neg=-5&bad=abc", nil)
	if got := queryInt(req, "limit", 100, 1, 500); got != 500 {
		t.Errorf("limit = %d, want the maximum", got)
	}
	if got := queryInt(req, "neg", 100, 1, 500); got != 1 {
		t.Errorf("negative = %d, want the minimum", got)
	}
	if got := queryInt(req, "bad", 42, 1, 500); got != 42 {
		t.Errorf("unparseable = %d, want the default", got)
	}
	if got := queryInt(req, "absent", 7, 1, 500); got != 7 {
		t.Errorf("absent = %d, want the default", got)
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("client"); !ok {
			t.Fatalf("request %d was refused within the limit", i+1)
		}
	}
	ok, retry := l.allow("client")
	if ok {
		t.Error("the fourth request should be refused")
	}
	if retry <= 0 {
		t.Error("a refusal must say how long to wait")
	}
	if ok, _ := l.allow("other"); !ok {
		t.Error("a different client must not be affected")
	}
}
