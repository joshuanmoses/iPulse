package speedtest

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode selects how much work a test does.
type Mode string

// Test modes.
const (
	// ModeFull is the full multi-stream download and upload measurement.
	ModeFull Mode = "full"
	// ModeLightweight is a small transfer used between full tests: enough to notice a
	// problem, cheap enough to run every few minutes.
	ModeLightweight Mode = "lightweight"
	// ModeManual is a full test requested by an operator.
	ModeManual Mode = "manual"
)

// Settings configures the engine, flattened from the YAML configuration.
type Settings struct {
	Provider          string
	Endpoints         []Endpoint
	EndpointSelection string
	Streams           int
	Warmup            time.Duration
	Duration          time.Duration
	UploadDuration    time.Duration
	MaxDownloadBytes  int64
	MaxUploadBytes    int64
	LightweightBytes  int64
	UploadEnabled     bool
	Timeout           time.Duration
	ExpectedDownload  float64
	ExpectedUpload    float64
}

// Result is a completed measurement.
type Result struct {
	Time     time.Time     `json:"time"`
	Mode     Mode          `json:"mode"`
	Provider string        `json:"provider"`
	Endpoint Endpoint      `json:"endpoint"`
	Duration time.Duration `json:"duration"`

	Latency  LatencySample `json:"latency"`
	Download Throughput    `json:"download"`
	Upload   Throughput    `json:"upload"`

	// Status is ok, partial or failed.
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Started and Finished bound the whole test, so the traffic monitor can attribute
	// the bytes to iPulse.
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// Status values.
const (
	StatusOK      = "ok"
	StatusPartial = "partial"
	StatusFailed  = "failed"
)

// TotalBytes returns everything transferred by the test, for self-traffic accounting.
func (r Result) TotalBytes() (rx, tx int64) {
	return r.Download.Bytes, r.Upload.Bytes
}

// Raw renders the measurement detail stored alongside the summary, so a result can be
// re-examined later without re-running the test.
func (r Result) Raw() string {
	payload := map[string]any{
		"download_slices": r.Download.Slices,
		"upload_slices":   r.Upload.Slices,
		"download_peak":   r.Download.PeakMbps,
		"upload_peak":     r.Upload.PeakMbps,
		"download_capped": r.Download.Capped,
		"upload_capped":   r.Upload.Capped,
		"latency_samples": r.Latency.Samples,
		"ttfb_ms":         float64(r.Latency.TTFB) / float64(time.Millisecond),
		"provider":        r.Provider,
		"endpoint":        r.Endpoint.Name,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

// Engine runs speed tests.
type Engine struct {
	set      Settings
	provider Provider

	mu sync.Mutex
	// selected caches the chosen endpoint so a test does not re-probe every endpoint
	// every time; the choice is refreshed periodically and after a failure.
	selected   *Endpoint
	selectedAt time.Time
	// running prevents two tests overlapping, which would make both wrong.
	running bool
}

// endpointTTL is how long a selected endpoint is reused before re-selecting.
const endpointTTL = 30 * time.Minute

// NewEngine builds an engine for the configured provider.
func NewEngine(set Settings) (*Engine, error) {
	if set.Provider == "" {
		set.Provider = "http"
	}
	p, err := Get(set.Provider)
	if err != nil {
		return nil, err
	}
	if len(set.Endpoints) == 0 {
		return nil, ErrNoEndpoints
	}
	if set.Timeout <= 0 {
		set.Timeout = 90 * time.Second
	}
	return &Engine{set: set, provider: p}, nil
}

// Settings returns the engine configuration.
func (e *Engine) Settings() Settings { return e.set }

// Running reports whether a test is in progress.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Run performs a test. Only one test runs at a time: two concurrent tests would compete
// for the same link and both results would be wrong.
func (e *Engine) Run(ctx context.Context, mode Mode) (Result, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return Result{}, fmt.Errorf("speedtest: a test is already running")
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	runCtx, cancel := context.WithTimeout(ctx, e.set.Timeout)
	defer cancel()

	res := Result{Time: time.Now(), Started: time.Now(), Mode: mode, Provider: e.provider.Name()}

	ep, err := e.selectEndpoint(runCtx)
	if err != nil {
		res.Status, res.Error, res.Finished = StatusFailed, err.Error(), time.Now()
		return res, err
	}
	res.Endpoint = ep

	session, err := e.provider.Prepare(runCtx, ep, e.set.Timeout)
	if err != nil {
		e.invalidateEndpoint()
		res.Status, res.Error, res.Finished = StatusFailed, err.Error(), time.Now()
		return res, err
	}
	defer session.Close()

	// Latency first: it is cheap, and measuring it before saturating the link gives the
	// unloaded figure that is comparable with the ICMP monitor's.
	latencySamples := 5
	if mode == ModeLightweight {
		latencySamples = 3
	}
	if lat, err := session.Latency(runCtx, latencySamples); err == nil {
		res.Latency = lat
	} else {
		res.Error = err.Error()
	}

	download, upload := e.paramsFor(mode)
	dl, err := session.Download(runCtx, download)
	res.Download = dl
	if err != nil {
		e.invalidateEndpoint()
		res.Status = StatusFailed
		res.Error = err.Error()
		res.Finished = time.Now()
		res.Duration = res.Finished.Sub(res.Started)
		return res, err
	}

	// Upload is skipped for lightweight tests: it is the expensive half, and the point
	// of the lightweight probe is to be cheap.
	if mode != ModeLightweight && e.set.UploadEnabled && ep.SupportsUpload() {
		ul, err := session.Upload(runCtx, upload)
		res.Upload = ul
		if err != nil {
			// A download result is still useful, so this is partial, not failed.
			res.Status = StatusPartial
			res.Error = err.Error()
		}
	}

	res.Finished = time.Now()
	res.Duration = res.Finished.Sub(res.Started)
	if res.Status == "" {
		res.Status = StatusOK
	}
	return res, nil
}

func (e *Engine) paramsFor(mode Mode) (download, upload Params) {
	switch mode {
	case ModeLightweight:
		// One stream, a short window and a small cap: enough to spot a collapse in
		// throughput between full tests without consuming real bandwidth.
		return Params{
			Streams: 1, Warmup: 500 * time.Millisecond, Duration: 3 * time.Second,
			MaxBytes: e.set.LightweightBytes, SliceInterval: 250 * time.Millisecond,
		}, Params{}
	default:
		download = Params{
			Streams: e.set.Streams, Warmup: e.set.Warmup, Duration: e.set.Duration,
			MaxBytes: e.set.MaxDownloadBytes, SliceInterval: 200 * time.Millisecond,
		}
		upload = Params{
			Streams: e.set.Streams, Warmup: e.set.Warmup, Duration: e.set.UploadDuration,
			MaxBytes: e.set.MaxUploadBytes, SliceInterval: 200 * time.Millisecond,
		}
		return download, upload
	}
}

// selectEndpoint chooses which endpoint to measure against.
func (e *Engine) selectEndpoint(ctx context.Context) (Endpoint, error) {
	e.mu.Lock()
	if e.selected != nil && time.Since(e.selectedAt) < endpointTTL {
		ep := *e.selected
		e.mu.Unlock()
		return ep, nil
	}
	e.mu.Unlock()

	if len(e.set.Endpoints) == 0 {
		return Endpoint{}, ErrNoEndpoints
	}

	var chosen Endpoint
	switch strings.ToLower(e.set.EndpointSelection) {
	case "first":
		chosen = e.set.Endpoints[0]
	case "random":
		chosen = e.set.Endpoints[rand.Intn(len(e.set.Endpoints))]
	default:
		best, err := e.lowestLatencyEndpoint(ctx)
		if err != nil {
			return Endpoint{}, err
		}
		chosen = best
	}

	e.mu.Lock()
	e.selected = &chosen
	e.selectedAt = time.Now()
	e.mu.Unlock()
	return chosen, nil
}

// lowestLatencyEndpoint picks the endpoint with the fastest TCP handshake. Connect time
// is the right criterion: it is cheap to measure and it correlates with the throughput
// a short test can achieve.
func (e *Engine) lowestLatencyEndpoint(ctx context.Context) (Endpoint, error) {
	type scored struct {
		ep      Endpoint
		connect time.Duration
		err     error
	}
	results := make([]scored, len(e.set.Endpoints))
	var wg sync.WaitGroup
	for i, ep := range e.set.Endpoints {
		wg.Add(1)
		go func(i int, ep Endpoint) {
			defer wg.Done()
			d, err := connectTime(ctx, ep.DownloadURL, 5*time.Second)
			results[i] = scored{ep: ep, connect: d, err: err}
		}(i, ep)
	}
	wg.Wait()

	usable := make([]scored, 0, len(results))
	for _, r := range results {
		if r.err == nil {
			usable = append(usable, r)
		}
	}
	if len(usable) == 0 {
		var firstErr error
		for _, r := range results {
			if r.err != nil {
				firstErr = r.err
				break
			}
		}
		return Endpoint{}, fmt.Errorf("%w: no endpoint answered (%v)", ErrNoEndpoints, firstErr)
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].connect < usable[j].connect })
	return usable[0].ep, nil
}

// UnavailableEndpoints probes every endpoint and reports which are unusable, so the
// caller can log them individually rather than only reporting the winner.
func (e *Engine) UnavailableEndpoints(ctx context.Context) map[string]string {
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ep := range e.set.Endpoints {
		wg.Add(1)
		go func(ep Endpoint) {
			defer wg.Done()
			if _, err := connectTime(ctx, ep.DownloadURL, 5*time.Second); err != nil {
				mu.Lock()
				out[ep.Name] = err.Error()
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	return out
}

// invalidateEndpoint forces re-selection on the next test, so a failing endpoint is not
// used repeatedly.
func (e *Engine) invalidateEndpoint() {
	e.mu.Lock()
	e.selected = nil
	e.mu.Unlock()
}

// SelectedEndpoint returns the currently chosen endpoint, if any.
func (e *Engine) SelectedEndpoint() (Endpoint, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.selected == nil {
		return Endpoint{}, false
	}
	return *e.selected, true
}

func connectTime(ctx context.Context, rawURL string, timeout time.Duration) (time.Duration, error) {
	u, err := url.Parse(expandBytes(rawURL, 1))
	if err != nil {
		return 0, err
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	_ = conn.Close()
	return elapsed, nil
}

// EndpointsFromConfig converts configured endpoints, skipping disabled ones.
func EndpointsFromConfig(in []ConfigEndpoint) []Endpoint {
	out := make([]Endpoint, 0, len(in))
	for _, e := range in {
		if e.Enabled != nil && !*e.Enabled {
			continue
		}
		out = append(out, Endpoint{
			Name:        e.Name,
			DownloadURL: e.DownloadURL,
			UploadURL:   e.UploadURL,
			LatencyURL:  e.LatencyURL,
			MaxStreams:  e.MaxStreams,
			Location:    e.Location,
		})
	}
	return out
}

// ConfigEndpoint mirrors the configuration shape without importing the config package,
// keeping internal/speedtest usable on its own.
type ConfigEndpoint struct {
	Name        string
	DownloadURL string
	UploadURL   string
	LatencyURL  string
	MaxStreams  int
	Location    string
	Enabled     *bool
}
