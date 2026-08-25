package speedtest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer serves the two endpoints a generic HTTP provider needs: a sized
// download and an upload sink. Running the whole engine against a local server makes the
// measurement path testable with no Internet access and no flaky third party.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte(i)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		size := int64(1 << 20)
		if v := r.URL.Query().Get("bytes"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				size = n
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		written := int64(0)
		for written < size {
			chunk := int64(len(block))
			if remaining := size - written; remaining < chunk {
				chunk = remaining
			}
			n, err := w.Write(block[:chunk])
			written += int64(n)
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strconv.FormatInt(n, 10)))
	})
	mux.HandleFunc("/tiny", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testEndpoint(srv *httptest.Server) Endpoint {
	return Endpoint{
		Name:        "local",
		DownloadURL: srv.URL + "/down?bytes={bytes}",
		UploadURL:   srv.URL + "/up",
		LatencyURL:  srv.URL + "/tiny",
		MaxStreams:  4,
		Location:    "loopback",
	}
}

func TestProviderRegistry(t *testing.T) {
	p, err := Get("http")
	if err != nil {
		t.Fatalf("the http provider must be registered: %v", err)
	}
	if p.Name() != "http" {
		t.Errorf("provider name = %q", p.Name())
	}
	if _, err := Get("nonexistent"); err == nil {
		t.Error("expected an error for an unknown provider")
	}
	found := false
	for _, n := range Providers() {
		if n == "http" {
			found = true
		}
	}
	if !found {
		t.Errorf("Providers() = %v, expected it to include http", Providers())
	}
}

func TestDownloadMeasurement(t *testing.T) {
	srv := newTestServer(t)
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), testEndpoint(srv), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	// The cap is set far above what loopback can transfer in the window, so this test
	// exercises the time-bounded path; the cap itself is covered separately.
	res, err := session.Download(context.Background(), Params{
		Streams: 2, Warmup: 100 * time.Millisecond, Duration: 400 * time.Millisecond,
		MaxBytes: 64 << 30, SliceInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Bytes <= 0 {
		t.Fatal("no bytes transferred")
	}
	if res.Mbps <= 0 {
		t.Errorf("throughput = %v Mbps", res.Mbps)
	}
	if res.Streams != 2 {
		t.Errorf("streams = %d, want 2", res.Streams)
	}
	if len(res.Slices) == 0 {
		t.Error("expected per-slice rates")
	}
	if res.P90Mbps <= 0 {
		t.Error("expected a p90 rate")
	}
	// The reported window is the measurement window only, excluding warm-up.
	if res.Duration > time.Second {
		t.Errorf("measurement window = %v, want about 400ms", res.Duration)
	}
	if res.Duration < 350*time.Millisecond {
		t.Errorf("measurement window = %v, want about 400ms", res.Duration)
	}
}

// TestDownloadByteCapIsEnforced is the safety property: a fast link must not be allowed
// to consume more than the configured allowance.
func TestDownloadByteCapIsEnforced(t *testing.T) {
	srv := newTestServer(t)
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), testEndpoint(srv), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	const cap = 4 << 20
	res, err := session.Download(context.Background(), Params{
		Streams: 2, Warmup: 0, Duration: 30 * time.Second,
		MaxBytes: cap, SliceInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !res.Capped {
		t.Error("expected the result to report that the cap ended the measurement")
	}
	// In-flight buffers mean a small overshoot is unavoidable, but it must be a small
	// multiple of the cap rather than whatever the link manages in one slice.
	if res.Bytes > 3*cap {
		t.Errorf("transferred %d bytes with a %d byte cap: enforcement is too coarse", res.Bytes, cap)
	}
	if res.Duration > 25*time.Second {
		t.Errorf("the cap should end the test early, took %v", res.Duration)
	}
}

func TestWarmupIsExcluded(t *testing.T) {
	srv := newTestServer(t)
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), testEndpoint(srv), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	res, err := session.Download(context.Background(), Params{
		Streams: 1, Warmup: 400 * time.Millisecond, Duration: 400 * time.Millisecond,
		MaxBytes: 64 << 30, SliceInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	// The reported duration is the measurement window only.
	if res.Duration > 900*time.Millisecond {
		t.Errorf("reported duration %v includes the warm-up", res.Duration)
	}
}

func TestUploadMeasurement(t *testing.T) {
	srv := newTestServer(t)
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), testEndpoint(srv), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	res, err := session.Upload(context.Background(), Params{
		Streams: 2, Warmup: 100 * time.Millisecond, Duration: time.Second,
		MaxBytes: 16 << 20, SliceInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if res.Bytes <= 0 || res.Mbps <= 0 {
		t.Errorf("upload measured nothing: %+v", res)
	}
}

func TestUploadUnsupportedEndpoint(t *testing.T) {
	srv := newTestServer(t)
	ep := testEndpoint(srv)
	ep.UploadURL = ""
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), ep, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if _, err := session.Upload(context.Background(), Params{Streams: 1, Duration: time.Second}); err != ErrUploadUnsupported {
		t.Errorf("expected ErrUploadUnsupported, got %v", err)
	}
	if ep.SupportsUpload() {
		t.Error("SupportsUpload should be false without an upload URL")
	}
}

func TestLatencyMeasurement(t *testing.T) {
	srv := newTestServer(t)
	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), testEndpoint(srv), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	lat, err := session.Latency(context.Background(), 5)
	if err != nil {
		t.Fatalf("latency: %v", err)
	}
	if lat.Samples != 5 {
		t.Errorf("samples = %d, want 5", lat.Samples)
	}
	if lat.RTT <= 0 {
		t.Error("expected a positive round trip")
	}
	if lat.TTFB <= 0 {
		t.Error("expected a positive time to first byte")
	}
	if lat.TCPConnect <= 0 {
		t.Error("expected a positive TCP connect time")
	}
	if lat.LossPct != 0 {
		t.Errorf("loss = %v%% against a local server", lat.LossPct)
	}
}

func TestEngineFullRun(t *testing.T) {
	srv := newTestServer(t)
	eng, err := NewEngine(Settings{
		Provider:          "http",
		Endpoints:         []Endpoint{testEndpoint(srv)},
		EndpointSelection: "first",
		Streams:           2,
		Warmup:            100 * time.Millisecond,
		Duration:          600 * time.Millisecond,
		UploadDuration:    600 * time.Millisecond,
		MaxDownloadBytes:  32 << 20,
		MaxUploadBytes:    8 << 20,
		LightweightBytes:  1 << 20,
		UploadEnabled:     true,
		Timeout:           30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := eng.Run(context.Background(), ModeFull)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != StatusOK {
		t.Errorf("status = %s (%s)", res.Status, res.Error)
	}
	if res.Download.Mbps <= 0 {
		t.Error("no download result")
	}
	if res.Upload.Mbps <= 0 {
		t.Error("no upload result")
	}
	if res.Latency.RTT <= 0 {
		t.Error("no latency result")
	}
	if res.Endpoint.Name != "local" {
		t.Errorf("endpoint = %q", res.Endpoint.Name)
	}
	if res.Provider != "http" {
		t.Errorf("provider = %q", res.Provider)
	}
	if res.Started.IsZero() || res.Finished.IsZero() || !res.Finished.After(res.Started) {
		t.Errorf("test window is wrong: %v -> %v", res.Started, res.Finished)
	}
	rx, tx := res.TotalBytes()
	if rx <= 0 || tx <= 0 {
		t.Errorf("self-traffic accounting needs both directions: rx=%d tx=%d", rx, tx)
	}
	if raw := res.Raw(); raw == "" {
		t.Error("expected a raw measurement record")
	}
}

// TestLightweightModeIsCheap checks the property that makes the frequent probe
// acceptable: no upload, one stream, a small transfer.
func TestLightweightModeIsCheap(t *testing.T) {
	srv := newTestServer(t)
	eng, err := NewEngine(Settings{
		Provider: "http", Endpoints: []Endpoint{testEndpoint(srv)},
		EndpointSelection: "first", Streams: 4,
		Duration: 10 * time.Second, UploadDuration: 10 * time.Second,
		MaxDownloadBytes: 512 << 20, MaxUploadBytes: 128 << 20,
		LightweightBytes: 1 << 20, UploadEnabled: true, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := eng.Run(context.Background(), ModeLightweight)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Upload.Bytes != 0 {
		t.Errorf("lightweight mode must not upload, sent %d bytes", res.Upload.Bytes)
	}
	if res.Download.Streams != 1 {
		t.Errorf("lightweight mode should use one stream, used %d", res.Download.Streams)
	}
	if res.Duration > 8*time.Second {
		t.Errorf("lightweight test took %v", res.Duration)
	}
}

func TestEngineRejectsConcurrentRuns(t *testing.T) {
	srv := newTestServer(t)
	eng, err := NewEngine(Settings{
		Provider: "http", Endpoints: []Endpoint{testEndpoint(srv)},
		EndpointSelection: "first", Streams: 1,
		Duration: 800 * time.Millisecond, MaxDownloadBytes: 32 << 20,
		LightweightBytes: 1 << 20, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = eng.Run(context.Background(), ModeFull)
		}(i)
	}
	wg.Wait()

	rejected := 0
	for _, err := range errs {
		if err != nil {
			rejected++
		}
	}
	if rejected != 1 {
		t.Errorf("expected exactly one run to be rejected, got %d failures: %v", rejected, errs)
	}
}

// TestEndpointSelectionSkipsDeadEndpoints proves the engine measures against something
// that answers rather than failing because the first configured endpoint is down.
func TestEndpointSelectionSkipsDeadEndpoints(t *testing.T) {
	srv := newTestServer(t)
	dead := Endpoint{Name: "dead", DownloadURL: "http://127.0.0.1:1/down"}
	eng, err := NewEngine(Settings{
		Provider: "http", Endpoints: []Endpoint{dead, testEndpoint(srv)},
		EndpointSelection: "latency", Streams: 1,
		Duration: 300 * time.Millisecond, MaxDownloadBytes: 8 << 20,
		LightweightBytes: 1 << 20, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := eng.Run(context.Background(), ModeFull)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Endpoint.Name != "local" {
		t.Errorf("selected %q, expected the reachable endpoint", res.Endpoint.Name)
	}

	unavailable := eng.UnavailableEndpoints(context.Background())
	if _, ok := unavailable["dead"]; !ok {
		t.Errorf("expected the dead endpoint to be reported: %v", unavailable)
	}
	if _, ok := unavailable["local"]; ok {
		t.Error("the working endpoint must not be reported as unavailable")
	}
}

func TestEngineFailsWhenNoEndpointAnswers(t *testing.T) {
	eng, err := NewEngine(Settings{
		Provider:  "http",
		Endpoints: []Endpoint{{Name: "dead", DownloadURL: "http://127.0.0.1:1/down"}},
		Duration:  time.Second, Timeout: 5 * time.Second, LightweightBytes: 1 << 20,
		MaxDownloadBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := eng.Run(context.Background(), ModeFull)
	if err == nil {
		t.Fatal("expected a failure when nothing answers")
	}
	if res.Status != StatusFailed {
		t.Errorf("status = %s, want failed", res.Status)
	}
	if res.Error == "" {
		t.Error("expected the failure to be described")
	}
}

// TestDownloadSurvivesRateLimiting is the resilience property for public endpoints: a
// mid-test 429 must not discard an otherwise good measurement.
func TestDownloadSurvivesRateLimiting(t *testing.T) {
	var requests atomic.Int64
	block := make([]byte, 64<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the first request, rate-limit the second, then serve normally.
		if n := requests.Add(1); n == 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		for i := 0; i < 8; i++ {
			if _, err := w.Write(block); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), Endpoint{
		Name: "limited", DownloadURL: srv.URL + "/down?bytes={bytes}", MaxStreams: 1,
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	res, err := session.Download(context.Background(), Params{
		Streams: 1, Warmup: 50 * time.Millisecond, Duration: 700 * time.Millisecond,
		MaxBytes: 64 << 20, SliceInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("a mid-test 429 must not fail the measurement: %v", err)
	}
	if res.Bytes <= 0 {
		t.Error("expected data to be transferred despite the rate limit")
	}
	if requests.Load() < 3 {
		t.Errorf("expected the stream to retry after the 429, saw %d requests", requests.Load())
	}
}

// TestDownloadFailsWhenImmediatelyRateLimited checks the other half: if nothing is ever
// transferred, the endpoint is reported as failing rather than retried forever.
func TestDownloadFailsWhenImmediatelyRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p, _ := Get("http")
	session, err := p.Prepare(context.Background(), Endpoint{
		Name: "blocked", DownloadURL: srv.URL + "/down", MaxStreams: 1,
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	start := time.Now()
	_, err = session.Download(context.Background(), Params{
		Streams: 1, Warmup: 0, Duration: 5 * time.Second, MaxBytes: 1 << 20,
	})
	if err == nil {
		t.Fatal("expected a failure when every request is refused")
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("failure took %v; it should be reported promptly", time.Since(start))
	}
}

func TestNewEngineValidation(t *testing.T) {
	if _, err := NewEngine(Settings{Provider: "http"}); err != ErrNoEndpoints {
		t.Errorf("expected ErrNoEndpoints, got %v", err)
	}
	if _, err := NewEngine(Settings{Provider: "bogus", Endpoints: []Endpoint{{Name: "x"}}}); err == nil {
		t.Error("expected an unknown-provider error")
	}
}

func TestExpandBytes(t *testing.T) {
	if got := expandBytes("https://example/down?bytes={bytes}", 1024); got != "https://example/down?bytes=1024" {
		t.Errorf("expandBytes = %q", got)
	}
	// A URL without the placeholder is used unchanged.
	if got := expandBytes("https://example/100MB.bin", 1024); got != "https://example/100MB.bin" {
		t.Errorf("expandBytes = %q", got)
	}
}

func TestEndpointsFromConfigSkipsDisabled(t *testing.T) {
	no := false
	yes := true
	out := EndpointsFromConfig([]ConfigEndpoint{
		{Name: "a", DownloadURL: "http://a", Enabled: &yes},
		{Name: "b", DownloadURL: "http://b", Enabled: &no},
		{Name: "c", DownloadURL: "http://c"}, // nil means enabled
	})
	if len(out) != 2 || out[0].Name != "a" || out[1].Name != "c" {
		t.Errorf("unexpected endpoints: %+v", out)
	}
}

func TestJitterOf(t *testing.T) {
	if got := jitterOf([]time.Duration{10 * time.Millisecond}); got != 0 {
		t.Errorf("single sample jitter = %v", got)
	}
	got := jitterOf([]time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 10 * time.Millisecond})
	if got != 10*time.Millisecond {
		t.Errorf("jitter = %v, want 10ms", got)
	}
}
