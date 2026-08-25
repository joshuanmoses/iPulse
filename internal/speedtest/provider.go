// Package speedtest measures throughput, latency and jitter.
//
// The provider abstraction is deliberate: iPulse must not depend on any single
// commercial speed-test service. A provider is anything that can serve a sized body and
// accept an upload, which includes an operator's own web server, so a site can measure
// against its own infrastructure and keep the results private.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Endpoint is one measurement target.
type Endpoint struct {
	Name        string
	DownloadURL string
	UploadURL   string
	LatencyURL  string
	MaxStreams  int
	Location    string
}

// SupportsUpload reports whether this endpoint can measure upload.
func (e Endpoint) SupportsUpload() bool { return e.UploadURL != "" }

// Params bounds one throughput measurement.
type Params struct {
	// Streams is the number of parallel connections.
	Streams int
	// Warmup is discarded before measurement so TCP slow-start is excluded.
	Warmup time.Duration
	// Duration bounds the measurement window.
	Duration time.Duration
	// MaxBytes caps the total transfer, so a fast link cannot consume a data allowance.
	MaxBytes int64
	// SliceInterval is the granularity of the per-slice rates used for the percentile.
	SliceInterval time.Duration
}

// Throughput is the result of a download or upload measurement.
type Throughput struct {
	Mbps float64 `json:"mbps"`
	// P90Mbps is the 90th percentile of per-slice rates. Reporting it next to the mean
	// makes a link with a fast peak but poor sustained rate visible.
	P90Mbps  float64       `json:"p90_mbps"`
	PeakMbps float64       `json:"peak_mbps"`
	Bytes    int64         `json:"bytes"`
	Duration time.Duration `json:"duration"`
	Streams  int           `json:"streams"`
	// Slices are the per-interval rates in Mbps, kept for the raw record.
	Slices []float64 `json:"slices,omitempty"`
	// Capped reports that the byte cap ended the measurement before its time window,
	// which means the link is faster than the configured cap can measure.
	Capped bool `json:"capped,omitempty"`
}

// LatencySample is the latency measurement taken as part of a speed test.
type LatencySample struct {
	RTT        time.Duration `json:"rtt"`
	Jitter     time.Duration `json:"jitter"`
	TCPConnect time.Duration `json:"tcp_connect"`
	TTFB       time.Duration `json:"ttfb"`
	DNS        time.Duration `json:"dns"`
	Samples    int           `json:"samples"`
	LossPct    float64       `json:"loss_percent"`
}

// Session is a prepared measurement against one endpoint.
type Session interface {
	Endpoint() Endpoint
	// Latency measures round trip, jitter and the connection set-up breakdown.
	Latency(ctx context.Context, samples int) (LatencySample, error)
	Download(ctx context.Context, p Params) (Throughput, error)
	Upload(ctx context.Context, p Params) (Throughput, error)
	Close() error
}

// Provider creates sessions.
type Provider interface {
	Name() string
	// Prepare validates the endpoint and returns a session. It performs no measurement.
	Prepare(ctx context.Context, ep Endpoint, timeout time.Duration) (Session, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Provider{}
)

// Register adds a provider implementation. Called from provider package init functions,
// so a new provider is added without touching the engine.
func Register(p Provider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[p.Name()] = p
}

// Get returns a registered provider.
func Get(name string) (Provider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("speedtest: no provider named %q (available: %s)", name, providerNames())
	}
	return p, nil
}

// Providers lists the registered provider names.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func providerNames() string {
	names := Providers()
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	if out == "" {
		return "none"
	}
	return out
}

// ErrNoEndpoints means no usable endpoint is configured.
var ErrNoEndpoints = errors.New("speedtest: no usable endpoint is configured")

// ErrUploadUnsupported means the selected endpoint cannot measure upload.
var ErrUploadUnsupported = errors.New("speedtest: the selected endpoint does not define an upload URL")
