// Package connectivity decides whether the Internet works, and when it does not, which
// layer is at fault.
//
// The design separates three concerns:
//
//   - Probes (this file) are cheap, independent reachability tests.
//   - Diagnostics (diagnostics.go) run the probes as a layered ladder, bottom up, and
//     collect evidence.
//   - Classification (classify.go) is a pure function from evidence to a conclusion, so
//     every outage classification is reproducible and unit-testable with no network.
package connectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/version"
)

// ProbeKind identifies what a probe tested.
type ProbeKind string

// Probe kinds.
const (
	ProbeTCP   ProbeKind = "tcp"
	ProbeHTTPS ProbeKind = "https"
	ProbeICMP  ProbeKind = "icmp"
)

// ProbeResult is the outcome of one reachability test.
type ProbeResult struct {
	Name     string        `json:"name"`
	Kind     ProbeKind     `json:"kind"`
	Target   string        `json:"target"`
	OK       bool          `json:"ok"`
	Duration time.Duration `json:"duration"`
	// Detail carries the HTTP status or the TLS peer, useful when a captive portal
	// answers with a redirect instead of the expected response.
	Detail string `json:"detail,omitempty"`
	Err    error  `json:"-"`
	Error  string `json:"error,omitempty"`
}

// MS returns the probe duration in milliseconds.
func (p ProbeResult) MS() float64 { return float64(p.Duration) / float64(time.Millisecond) }

// TCPProbe opens a TCP connection and measures the handshake.
func TCPProbe(ctx context.Context, name, address string, timeout time.Duration) ProbeResult {
	res := ProbeResult{Name: name, Kind: ProbeTCP, Target: address}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", address)
	res.Duration = time.Since(start)
	if err != nil {
		res.Err = err
		res.Error = trimError(err)
		return res
	}
	_ = conn.Close()
	res.OK = true
	return res
}

// HTTPSProbe performs a full HTTPS request, which verifies DNS (when the target is a
// name), TCP, the TLS handshake and an HTTP response - the whole path a real client
// uses. A captive portal that intercepts traffic usually fails here even when TCP
// probes succeed, which is why this probe exists alongside them.
func HTTPSProbe(ctx context.Context, client *http.Client, name, url string, timeout time.Duration) ProbeResult {
	res := ProbeResult{Name: name, Kind: ProbeHTTPS, Target: url}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err
		res.Error = trimError(err)
		return res
	}
	req.Header.Set("User-Agent", version.UserAgent)
	// Ask intermediaries not to answer from cache: a cached response would make a
	// broken path look healthy.
	req.Header.Set("Cache-Control", "no-cache")

	start := time.Now()
	resp, err := client.Do(req)
	res.Duration = time.Since(start)
	if err != nil {
		res.Err = err
		res.Error = trimError(err)
		return res
	}
	defer resp.Body.Close()
	// Read and discard a bounded amount: some endpoints only complete the exchange once
	// the body is consumed, and the cap keeps the probe cheap.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	res.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		res.Detail += ", TLS " + tlsVersionName(resp.TLS.Version) +
			", cn=" + resp.TLS.PeerCertificates[0].Subject.CommonName
	}
	// 2xx and 3xx both prove the path works. A 5xx from the endpoint means the network
	// is fine and the far end is not, which is not an iPulse fault to report as an
	// outage, so it counts as reachable but is recorded in Detail.
	res.OK = resp.StatusCode < 500
	if !res.OK {
		res.Err = fmt.Errorf("unexpected status %d", resp.StatusCode)
		res.Error = res.Err.Error()
	}
	return res
}

// NewHTTPClient builds the HTTP client used by probes and speed tests.
//
// Redirects are followed (captive portals rely on them, and following one lets the probe
// report what actually answered), connection reuse is disabled for probes so each test
// measures a fresh path, and the TLS configuration is left at Go's secure defaults: a
// monitoring agent must never be the thing that accepts a bad certificate.
func NewHTTPClient(timeout time.Duration, keepAlive bool) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     !keepAlive,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "unknown"
}

// trimError shortens the verbose wrapping Go puts on network errors so log fields stay
// readable, while keeping the part that identifies the failure.
func trimError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// "dial tcp 1.1.1.1:443: connect: connection refused" -> "connection refused"
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg)-i < 48 {
		msg = msg[i+2:]
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return strings.ReplaceAll(msg, "\n", " ")
}
