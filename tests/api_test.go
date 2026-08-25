package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/api"
	"github.com/ipulse/ipulse/internal/config"
)

// startAPI runs an agent with the dashboard enabled on an ephemeral port and returns the
// base URL. Binding to port 0 keeps parallel test runs from colliding.
func startAPI(t *testing.T, mutate func(*config.Config)) (*agent.Agent, string) {
	t.Helper()
	cfg := offlineConfig(t)
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Address = "127.0.0.1"
	cfg.Dashboard.Port = freePort(t)
	if mutate != nil {
		mutate(cfg)
	}
	revalidate(t, cfg)

	a, err := agent.New(agent.Options{Config: cfg, Mode: "foreground"})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	srv, err := api.New(api.Options{Config: cfg, Backend: a, Logger: a.Logger()})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	a.SetServer(srv)

	_, stop := runAgent(t, a)
	t.Cleanup(stop)

	base := "http://" + srv.Addr()
	// The listener is bound by Run, so wait for it rather than assuming.
	client := newHTTPClient()
	eventually(t, 20*time.Second, "the API to accept connections", func() bool {
		resp, err := client.Get(base + "/api/v1/health")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	})
	return a, base
}

// TestAPISurface walks every documented read endpoint. The assertion is deliberately
// shallow — each must answer 200 with a JSON object — because the point is that the
// whole surface is reachable and none of it panics on an agent with almost no data yet.
func TestAPISurface(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	endpoints := []string{
		"status", "health", "speed", "speed/history", "events", "events/catalog",
		"outages", "connections", "destinations", "interfaces", "public-ip", "config",
		"measurements?metric=latency_ms", "traffic", "threats", "routes", "tasks",
		"privileges", "summary", "baselines",
	}
	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			resp, err := client.Get(base + "/api/v1/" + ep)
			if err != nil {
				t.Fatalf("GET %s: %v", ep, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: status %d: %s", ep, resp.StatusCode, body)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("GET %s: content type %q", ep, ct)
			}
			var v any
			if err := json.Unmarshal(body, &v); err != nil {
				t.Fatalf("GET %s: response is not JSON: %v", ep, err)
			}
		})
	}
}

// TestAPISecurityHeaders checks the headers that make a local dashboard safe to leave
// running: no sniffing, no framing, no referrer leakage, a content policy, and above all
// no CORS header, which is what stops another origin reading the responses.
func TestAPISecurityHeaders(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	resp, err := client.Get(base + "/api/v1/status")
	if err != nil {
		t.Fatalf("GET status: %v", err)
	}
	defer resp.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("no Content-Security-Policy header")
	} else if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("the content policy allows eval: %s", csp)
	}
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("%s is set to %q; the API must not be readable cross-origin", h, v)
		}
	}
}

// TestAPIHostAllowList is the DNS-rebinding defence. A request carrying a Host the
// operator did not allow must be refused even though it arrived on loopback.
func TestAPIHostAllowList(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a request with a foreign Host header returned %d, want 403", resp.StatusCode)
	}
	var e apiError
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("the refusal is not JSON: %v", err)
	}
	if e.Code != "host_not_allowed" {
		t.Errorf("error code %q, want host_not_allowed", e.Code)
	}
}

// TestAPIToken checks that a configured token is required, that a wrong token is
// refused, and that both header forms work.
func TestAPIToken(t *testing.T) {
	const token = "an-example-token-long-enough"
	_, base := startAPI(t, func(c *config.Config) { c.Dashboard.AuthToken = token })
	client := newHTTPClient()

	resp, err := client.Get(base + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unauthenticated request returned %d, want 401", resp.StatusCode)
	}

	for name, set := range map[string]func(*http.Request){
		"X-iPulse-Token": func(r *http.Request) { r.Header.Set("X-iPulse-Token", token) },
		"Authorization":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
	} {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/status", nil)
		set(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, resp.StatusCode)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/status", nil)
	req.Header.Set("X-iPulse-Token", token+"x")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong token returned %d, want 401", resp.StatusCode)
	}
}

// TestAPIErrors checks that the documented failure modes are what actually happens:
// unknown paths 404, wrong methods 405 with an Allow header, and bad parameters 400 with
// a machine-readable code.
func TestAPIErrors(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	cases := []struct {
		name, method, path string
		want               int
		wantCode           string
	}{
		{"unknown endpoint", http.MethodGet, "/api/v1/nope", http.StatusNotFound, ""},
		{"wrong method", http.MethodPost, "/api/v1/status", http.StatusMethodNotAllowed, ""},
		{"read endpoint via POST", http.MethodPost, "/api/v1/events", http.StatusMethodNotAllowed, ""},
		{"bad severity", http.MethodGet, "/api/v1/events?severity=bogus", http.StatusBadRequest, ""},
		{"bad window", http.MethodGet, "/api/v1/events?since=yesterday", http.StatusBadRequest, ""},
		{"missing metric", http.MethodGet, "/api/v1/measurements", http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, base+tc.path, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("%s %s: status %d, want %d: %s", tc.method, tc.path, resp.StatusCode, tc.want, body)
			}
			if resp.StatusCode == http.StatusMethodNotAllowed && resp.Header.Get("Allow") == "" {
				t.Error("a 405 was returned without an Allow header")
			}
			var e apiError
			if err := json.Unmarshal(body, &e); err != nil {
				t.Fatalf("the error response is not JSON: %s", body)
			}
			if e.Message == "" {
				t.Error("the error response has no message")
			}
			if tc.wantCode != "" && e.Code != tc.wantCode {
				t.Errorf("error code %q, want %q", e.Code, tc.wantCode)
			}
		})
	}
}

// TestSinceWindowParsing guards a real bug: "30m" once parsed as thirty months, which
// silently turned the dashboard's fifteen-minute view into a two-and-a-half-year query.
func TestSinceWindowParsing(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	valid := []string{"15m", "30m", "1h", "6h", "24h", "7d", "2w", "3mo", "1y", "90s"}
	for _, w := range valid {
		resp, err := client.Get(base + "/api/v1/events?since=" + w)
		if err != nil {
			t.Fatalf("since=%s: %v", w, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("since=%s: status %d, want 200", w, resp.StatusCode)
		}
	}
	for _, w := range []string{"-1h", "0", "0s", "forever", "10x"} {
		resp, err := client.Get(base + "/api/v1/events?since=" + w)
		if err != nil {
			t.Fatalf("since=%s: %v", w, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("since=%s: status %d, want 400", w, resp.StatusCode)
		}
	}
}

// TestDashboardIsServed checks the embedded dashboard: the root must render the page
// directly rather than redirecting, and a missing asset must 404 rather than being
// answered with the index page.
func TestDashboardIsServed(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	if !strings.Contains(strings.ToLower(page), "<!doctype html") {
		t.Error("the root did not return the dashboard page")
	}
	// No external requests: it is what lets the content policy stay strict, and it is
	// also the privacy guarantee that the dashboard contacts nothing.
	for _, marker := range []string{"http://cdn", "https://cdn", "//unpkg.com", "//cdnjs.", "googleapis.com"} {
		if strings.Contains(page, marker) {
			t.Errorf("the dashboard references an external resource: %s", marker)
		}
	}

	for _, asset := range []string{"/style.css", "/app.js"} {
		resp, err := client.Get(base + asset)
		if err != nil {
			t.Fatalf("GET %s: %v", asset, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", asset, resp.StatusCode)
		}
	}

	resp, err = client.Get(base + "/definitely-not-here.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a missing asset returned %d, want 404", resp.StatusCode)
	}
}

// TestTestEndpointsAreRateLimited checks that the endpoints which start real network
// activity cannot be used as an amplifier. The test collector is a local probe, so the
// requests themselves are harmless.
func TestTestEndpointsAreRateLimited(t *testing.T) {
	_, base := startAPI(t, func(c *config.Config) { c.Dashboard.RateLimitPerMinute = 3 })
	client := newHTTPClient()

	limited := false
	for i := 0; i < 8; i++ {
		resp, err := client.Post(base+"/api/v1/tests/connectivity", "application/json", nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("a 429 was returned without a Retry-After header")
			}
			break
		}
	}
	if !limited {
		t.Error("the test endpoints were never rate limited")
	}
}

// TestDisabledCollectorHasNoTestEndpoint documents the 404 an operator sees when a
// collector is switched off: the task is not registered, so there is nothing to trigger.
func TestDisabledCollectorHasNoTestEndpoint(t *testing.T) {
	_, base := startAPI(t, nil) // the offline configuration disables speed testing
	client := newHTTPClient()

	resp, err := client.Post(base+"/api/v1/tests/speed", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a disabled collector", resp.StatusCode)
	}
}

// TestConfigEndpointRedactsSecrets checks that the effective configuration can be shared
// in a bug report without leaking the dashboard token.
func TestConfigEndpointRedactsSecrets(t *testing.T) {
	const token = "super-secret-token-value"
	_, base := startAPI(t, func(c *config.Config) { c.Dashboard.AuthToken = token })
	client := newHTTPClient()

	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/config", nil)
	req.Header.Set("X-iPulse-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), token) {
		t.Error("the config endpoint returned the dashboard token in clear text")
	}
}

type apiError struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// TestUnknownAPIPathIsAlwaysNotFound checks that a missing endpoint reads as missing
// whatever verb was used. Answering 405 to a POST at a path that does not exist would
// send the caller looking for the wrong mistake.
func TestUnknownAPIPathIsAlwaysNotFound(t *testing.T) {
	_, base := startAPI(t, nil)
	client := newHTTPClient()

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, base+"/api/v1/does-not-exist", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s /api/v1/does-not-exist: status %d, want 404", method, resp.StatusCode)
		}
		var e apiError
		if err := json.Unmarshal(body, &e); err != nil || e.Code != "unknown_endpoint" {
			t.Errorf("%s: unexpected body %s", method, body)
		}
	}
}
