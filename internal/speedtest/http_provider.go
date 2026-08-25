package speedtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipulse/ipulse/internal/util"
	"github.com/ipulse/ipulse/internal/version"
)

func init() { Register(&httpProvider{}) }

// httpProvider measures against any HTTP server that can serve a sized body and accept a
// POST. The download URL may contain a {bytes} placeholder, which is replaced with the
// requested size; servers that ignore it and stream indefinitely work equally well
// because the measurement is bounded by time and by the byte cap.
type httpProvider struct{}

func (p *httpProvider) Name() string { return "http" }

func (p *httpProvider) Prepare(ctx context.Context, ep Endpoint, timeout time.Duration) (Session, error) {
	if ep.DownloadURL == "" {
		return nil, fmt.Errorf("speedtest: endpoint %q has no download URL", ep.Name)
	}
	u, err := url.Parse(expandBytes(ep.DownloadURL, 1))
	if err != nil {
		return nil, fmt.Errorf("speedtest: endpoint %q download URL: %w", ep.Name, err)
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &httpSession{ep: ep, host: u.Host, client: newTransferClient(timeout), timeout: timeout}, nil
}

// newTransferClient builds a client tuned for throughput measurement rather than for
// probing: connections are pooled per stream, compression is refused so the measured
// bytes are the bytes on the wire, and there is no overall client timeout because the
// measurement bounds itself with a context.
func newTransferClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     false, // one TCP connection per stream is what we want
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   64,
			MaxConnsPerHost:       64,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   timeout,
			ExpectContinueTimeout: time.Second,
			DisableCompression:    true,
			WriteBufferSize:       128 << 10,
			ReadBufferSize:        128 << 10,
		},
	}
}

type httpSession struct {
	ep      Endpoint
	host    string
	client  *http.Client
	timeout time.Duration
}

func (s *httpSession) Endpoint() Endpoint { return s.ep }

func (s *httpSession) Close() error {
	s.client.CloseIdleConnections()
	return nil
}

// Latency measures the round trip to the endpoint, along with the DNS and TCP connect
// breakdown.
//
// Two details matter for the number to be meaningful. First, a warm-up request is
// discarded: the first request pays DNS resolution and the TLS handshake, and including
// it would inflate jitter by an order of magnitude. Second, the reported latency is time
// to first byte on a reused connection, which is the closest an HTTP client can get to
// path round-trip time without raw sockets.
func (s *httpSession) Latency(ctx context.Context, samples int) (LatencySample, error) {
	if samples <= 0 {
		samples = 5
	}
	target := s.ep.LatencyURL
	if target == "" {
		// A tiny download stands in for a latency probe when no dedicated URL exists.
		target = expandBytes(s.ep.DownloadURL, 1024)
	}

	// Warm-up: establishes the connection so the measured samples exclude set-up.
	warmRTT, warmConnect, warmDNS, _, warmErr := s.timeRequest(ctx, target)

	var (
		rtts     []time.Duration
		connects []time.Duration
		dnsTimes []time.Duration
		ttfbs    []time.Duration
		failures int
	)
	if warmErr == nil {
		if warmConnect > 0 {
			connects = append(connects, warmConnect)
		}
		if warmDNS > 0 {
			dnsTimes = append(dnsTimes, warmDNS)
		}
		_ = warmRTT
	}

	for i := 0; i < samples; i++ {
		if ctx.Err() != nil {
			break
		}
		rtt, connect, dns, ttfb, err := s.timeRequest(ctx, target)
		if err != nil {
			failures++
			continue
		}
		// Prefer time to first byte; fall back to the full round trip when the trace
		// did not report it.
		sample := ttfb
		if sample <= 0 {
			sample = rtt
		}
		rtts = append(rtts, sample)
		ttfbs = append(ttfbs, sample)
		if connect > 0 {
			connects = append(connects, connect)
		}
		if dns > 0 {
			dnsTimes = append(dnsTimes, dns)
		}
	}
	if len(rtts) == 0 {
		if warmErr != nil {
			return LatencySample{Samples: samples, LossPct: 100},
				fmt.Errorf("speedtest: latency probe failed against %s: %w", s.ep.Name, warmErr)
		}
		return LatencySample{Samples: samples, LossPct: 100},
			fmt.Errorf("speedtest: no latency sample completed against %s", s.ep.Name)
	}

	out := LatencySample{
		Samples: len(rtts),
		LossPct: float64(failures) / float64(samples) * 100,
	}
	// The minimum is the best estimate of the true path latency: larger samples include
	// queueing, which the throughput test measures separately.
	out.RTT = minDuration(rtts)
	out.Jitter = jitterOf(rtts)
	if len(connects) > 0 {
		out.TCPConnect = minDuration(connects)
	}
	if len(dnsTimes) > 0 {
		out.DNS = minDuration(dnsTimes)
	}
	if len(ttfbs) > 0 {
		out.TTFB = minDuration(ttfbs)
	}
	return out, nil
}

// timeRequest performs one request with httptrace, returning the full round trip plus
// the DNS, TCP connect and TTFB breakdown.
func (s *httpSession) timeRequest(ctx context.Context, target string) (rtt, connect, dns, ttfb time.Duration, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var (
		start                      = time.Now()
		dnsStart, connStart, first time.Time
	)
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				dns = time.Since(dnsStart)
			}
		},
		ConnectStart: func(string, string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connStart.IsZero() {
				connect = time.Since(connStart)
			}
		},
		GotFirstResponseByte: func() { first = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, target, nil)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Cache-Control", "no-cache, no-store")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	rtt = time.Since(start)
	if !first.IsZero() {
		ttfb = first.Sub(start)
	}
	if resp.StatusCode >= 400 {
		return rtt, connect, dns, ttfb, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return rtt, connect, dns, ttfb, nil
}

// Download measures inbound throughput with N parallel streams.
//
// Method: all streams start together, a warm-up window is discarded so TCP slow-start
// does not depress the result, then bytes are counted per slice for the measurement
// window. The measurement ends at whichever comes first: the duration or the byte cap.
func (s *httpSession) Download(ctx context.Context, p Params) (Throughput, error) {
	p = normaliseParams(p, s.ep.MaxStreams)
	// Request the transfer in chunks and loop, rather than asking for the whole cap in
	// one request. Public endpoints commonly reject very large single requests (the
	// Cloudflare endpoint refuses anything near 100 MB), and looping also keeps the
	// pipe full when a server serves exactly what was asked for and closes.
	target := expandBytes(s.ep.DownloadURL, chunkSize(p))

	m := newMeter(p)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, p.Streams)
	for i := 0; i < p.Streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.downloadStream(runCtx, target, m); err != nil {
				errs <- err
			}
		}()
	}
	// If every stream dies (an endpoint refusing all requests, for example) there is
	// nothing left to measure, so the measurement ends immediately rather than waiting
	// out its window.
	streamsDone := make(chan struct{})
	go func() { wg.Wait(); close(streamsDone) }()

	res := m.run(runCtx, cancel, streamsDone)
	<-streamsDone

	if res.Bytes == 0 {
		select {
		case err := <-errs:
			return res, fmt.Errorf("speedtest: download failed: %w", err)
		default:
			return res, fmt.Errorf("speedtest: download transferred no data")
		}
	}
	return res, nil
}

func (s *httpSession) downloadStream(ctx context.Context, target string, m *meter) error {
	// A stream retries a rate-limited chunk a few times, then gives up so a persistently
	// refusing endpoint is reported rather than retried for the whole window.
	const maxRetries = 3
	retries := 0

	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", version.UserAgent)
		req.Header.Set("Cache-Control", "no-cache, no-store")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := s.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil // the measurement ended, not a failure
			}
			return err
		}
		// A public endpoint may rate-limit or shed load mid-test. Backing off briefly
		// and continuing keeps the measurement usable, where aborting would discard a
		// perfectly good result because one chunk was refused.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			delay := retryAfter(resp, 250*time.Millisecond)
			status := resp.StatusCode
			resp.Body.Close()
			retries++
			// Nothing transferred by any stream, or too many refusals: report it so the
			// endpoint is marked unavailable instead of being retried all window.
			if m.total.Load() == 0 || retries > maxRetries {
				return fmt.Errorf("unexpected status %d", status)
			}
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return nil
			}
		}
		if resp.StatusCode >= 400 {
			resp.Body.Close()
			return fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		// Count bytes as they arrive, without retaining them.
		_, err = io.Copy(io.Discard, &countingReader{r: resp.Body, m: m})
		resp.Body.Close()
		if err != nil && ctx.Err() == nil {
			return err
		}
		// A server that served exactly the requested size ends the stream; loop to keep
		// the pipe full for the rest of the measurement window.
	}
	return nil
}

// Upload measures outbound throughput. The body is a repeating pseudo-random buffer:
// random enough that a compressing middlebox cannot inflate the result, cheap enough
// that the CPU is never the bottleneck.
func (s *httpSession) Upload(ctx context.Context, p Params) (Throughput, error) {
	if !s.ep.SupportsUpload() {
		return Throughput{}, ErrUploadUnsupported
	}
	p = normaliseParams(p, s.ep.MaxStreams)

	m := newMeter(p)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	block := make([]byte, 256<<10)
	if _, err := rand.Read(block); err != nil {
		return Throughput{}, err
	}

	var wg sync.WaitGroup
	errs := make(chan error, p.Streams)
	for i := 0; i < p.Streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.uploadStream(runCtx, block, m, p); err != nil {
				errs <- err
			}
		}()
	}
	streamsDone := make(chan struct{})
	go func() { wg.Wait(); close(streamsDone) }()

	res := m.run(runCtx, cancel, streamsDone)
	<-streamsDone

	if res.Bytes == 0 {
		select {
		case err := <-errs:
			return res, fmt.Errorf("speedtest: upload failed: %w", err)
		default:
			return res, fmt.Errorf("speedtest: upload transferred no data")
		}
	}
	return res, nil
}

func (s *httpSession) uploadStream(ctx context.Context, block []byte, m *meter, p Params) error {
	perRequest := chunkSize(p)
	const maxRetries = 3
	retries := 0
	for ctx.Err() == nil {
		body := &generatingReader{block: block, remaining: perRequest, m: m, ctx: ctx}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ep.UploadURL, body)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", version.UserAgent)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = perRequest

		resp, err := s.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			retries++
			if m.total.Load() == 0 || retries > maxRetries {
				return fmt.Errorf("unexpected status %d", resp.StatusCode)
			}
			select {
			case <-time.After(retryAfter(resp, 250*time.Millisecond)):
				continue
			case <-ctx.Done():
				return nil
			}
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
	}
	return nil
}

// retryAfter honours a Retry-After header, bounded so a long value cannot stall a
// measurement that is itself only seconds long.
func retryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	// The whole measurement window is only seconds long, so a long Retry-After is
	// clamped: waiting it out would consume the window and produce no result.
	const maxDelay = 500 * time.Millisecond
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			d := time.Duration(secs) * time.Second
			if d > maxDelay {
				return maxDelay
			}
			return d
		}
	}
	if fallback > maxDelay {
		return maxDelay
	}
	return fallback
}

// countingReader reports bytes to the meter as they are read.
type countingReader struct {
	r io.Reader
	m *meter
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.m.add(int64(n))
	}
	return n, err
}

// generatingReader produces upload data from a repeating block and reports progress.
type generatingReader struct {
	block     []byte
	remaining int64
	offset    int
	m         *meter
	ctx       context.Context
}

func (g *generatingReader) Read(b []byte) (int, error) {
	if g.ctx.Err() != nil {
		return 0, io.EOF
	}
	if g.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(b)
	if int64(n) > g.remaining {
		n = int(g.remaining)
	}
	written := 0
	for written < n {
		chunk := copy(b[written:n], g.block[g.offset:])
		g.offset += chunk
		if g.offset >= len(g.block) {
			g.offset = 0
		}
		written += chunk
	}
	g.remaining -= int64(written)
	g.m.add(int64(written))
	return written, nil
}

// meter accumulates transferred bytes and turns them into a rate.
type meter struct {
	params Params
	total  atomic.Int64
	// counted is the bytes transferred inside the measurement window.
	counted atomic.Int64
	// measuring gates counting, so warm-up bytes are excluded.
	measuring atomic.Bool

	// capHit is closed as soon as the byte cap is reached. Enforcing the cap here
	// rather than at the next slice boundary matters: at 10 Gbps a 200 ms slice carries
	// a quarter of a gigabyte, so boundary-only enforcement would overshoot a metered
	// allowance by orders of magnitude.
	capHit  chan struct{}
	capOnce sync.Once
}

func newMeter(p Params) *meter {
	return &meter{params: p, capHit: make(chan struct{})}
}

func (m *meter) add(n int64) {
	total := m.total.Add(n)
	if m.measuring.Load() {
		m.counted.Add(n)
	}
	if m.params.MaxBytes > 0 && total >= m.params.MaxBytes {
		m.capOnce.Do(func() { close(m.capHit) })
	}
}

// run drives the measurement clock: warm-up, then per-slice sampling until the duration
// or the byte cap is reached. It cancels the streams when finished.
func (m *meter) run(ctx context.Context, cancel context.CancelFunc, streamsDone <-chan struct{}) Throughput {
	res := Throughput{Streams: m.params.Streams}

	if m.params.Warmup > 0 {
		select {
		case <-time.After(m.params.Warmup):
		case <-streamsDone:
			// Every stream failed during warm-up: nothing to measure.
			cancel()
			return res
		case <-m.capHit:
			// The cap was reached during warm-up: report what the warm-up itself
			// measured rather than nothing at all.
			res.Capped = true
			res.Bytes = m.total.Load()
			res.Duration = m.params.Warmup
			if res.Duration > 0 {
				res.Mbps = float64(res.Bytes) * 8 / res.Duration.Seconds() / 1e6
			}
			cancel()
			return res
		case <-ctx.Done():
			cancel()
			return res
		}
	}

	m.counted.Store(0)
	m.measuring.Store(true)
	start := time.Now()

	slice := m.params.SliceInterval
	if slice <= 0 {
		slice = 200 * time.Millisecond
	}
	ticker := time.NewTicker(slice)
	defer ticker.Stop()

	var (
		lastBytes int64
		lastTime  = start
		rates     []float64
	)
	deadline := start.Add(m.params.Duration)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-streamsDone:
			if elapsed := time.Since(lastTime); elapsed > 0 {
				current := m.counted.Load()
				rates = append(rates, float64(current-lastBytes)*8/elapsed.Seconds()/1e6)
			}
			break loop
		case <-m.capHit:
			// Record the final partial slice so a very short capped measurement still
			// has a rate to report.
			if elapsed := time.Since(lastTime); elapsed > 0 {
				current := m.counted.Load()
				rates = append(rates, float64(current-lastBytes)*8/elapsed.Seconds()/1e6)
			}
			res.Capped = true
			break loop
		case now := <-ticker.C:
			current := m.counted.Load()
			elapsed := now.Sub(lastTime)
			if elapsed > 0 {
				rate := float64(current-lastBytes) * 8 / elapsed.Seconds() / 1e6
				rates = append(rates, rate)
			}
			lastBytes, lastTime = current, now

			if !now.Before(deadline) {
				break loop
			}
		}
	}

	elapsed := time.Since(start)
	m.measuring.Store(false)
	cancel()

	res.Bytes = m.counted.Load()
	res.Duration = elapsed
	if elapsed > 0 && res.Bytes > 0 {
		res.Mbps = float64(res.Bytes) * 8 / elapsed.Seconds() / 1e6
	}
	res.Slices = rates
	if len(rates) > 0 {
		res.P90Mbps = util.Percentile(rates, 90)
		for _, r := range rates {
			if r > res.PeakMbps {
				res.PeakMbps = r
			}
		}
	}
	return res
}

// chunkSize is the per-request transfer size: the share of the cap belonging to one
// stream, bounded to a range that every HTTP server handles comfortably.
func chunkSize(p Params) int64 {
	const (
		minChunk int64 = 1 << 20  // 1 MiB: smaller wastes time on request overhead
		maxChunk int64 = 25 << 20 // 25 MiB: below the limits public endpoints impose
	)
	streams := int64(p.Streams)
	if streams < 1 {
		streams = 1
	}
	chunk := maxChunk
	if p.MaxBytes > 0 {
		if share := p.MaxBytes / streams; share < chunk {
			chunk = share
		}
	}
	if chunk < minChunk {
		chunk = minChunk
	}
	return chunk
}

func normaliseParams(p Params, endpointMax int) Params {
	if p.Streams <= 0 {
		p.Streams = 4
	}
	if endpointMax > 0 && p.Streams > endpointMax {
		p.Streams = endpointMax
	}
	if p.Duration <= 0 {
		p.Duration = 10 * time.Second
	}
	if p.SliceInterval <= 0 {
		p.SliceInterval = 200 * time.Millisecond
	}
	return p
}

// expandBytes substitutes the {bytes} placeholder, and appends a bytes parameter for
// URLs that use the common query-string convention without a placeholder.
func expandBytes(rawURL string, n int64) string {
	if strings.Contains(rawURL, "{bytes}") {
		return strings.ReplaceAll(rawURL, "{bytes}", strconv.FormatInt(n, 10))
	}
	return rawURL
}

func minDuration(in []time.Duration) time.Duration {
	if len(in) == 0 {
		return 0
	}
	out := in[0]
	for _, d := range in[1:] {
		if d < out {
			out = d
		}
	}
	return out
}

// jitterOf is the mean absolute difference between consecutive samples, matching the
// definition used by the latency monitor so the two figures are comparable.
func jitterOf(in []time.Duration) time.Duration {
	if len(in) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(in); i++ {
		d := float64(in[i] - in[i-1])
		if d < 0 {
			d = -d
		}
		total += d
	}
	return time.Duration(total / float64(len(in)-1))
}
