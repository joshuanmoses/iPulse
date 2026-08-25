package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/speedtest"
	"github.com/ipulse/ipulse/internal/traffic"
	"github.com/ipulse/ipulse/internal/util"
)

// speedMonitor runs the speed tests and reports performance against the operator's ISP
// expectations.
//
// Two tiers, as configured: a cheap lightweight probe every few minutes, and a full
// multi-stream test on a long interval. The full test is the only thing iPulse does that
// deliberately consumes bandwidth, so it is bounded by time and bytes, skipped when the
// link is already busy, and always attributed to iPulse so it cannot trigger its own
// traffic anomalies.
type speedMonitor struct {
	a      *Agent
	engine *speedtest.Engine
	self   *traffic.SelfTraffic

	dlShortfall *gate
	ulShortfall *gate
}

func newSpeedMonitor(a *Agent, self *traffic.SelfTraffic) (*speedMonitor, error) {
	cfg := a.cfg.SpeedTest
	endpoints := make([]speedtest.ConfigEndpoint, 0, len(cfg.Endpoints))
	for _, e := range cfg.Endpoints {
		endpoints = append(endpoints, speedtest.ConfigEndpoint{
			Name: e.Name, DownloadURL: e.DownloadURL, UploadURL: e.UploadURL,
			LatencyURL: e.LatencyURL, MaxStreams: e.MaxStreams, Location: e.Location,
			Enabled: e.Enabled,
		})
	}
	engine, err := speedtest.NewEngine(speedtest.Settings{
		Provider:          cfg.Provider,
		Endpoints:         speedtest.EndpointsFromConfig(endpoints),
		EndpointSelection: cfg.EndpointSelection,
		Streams:           cfg.Streams,
		Warmup:            cfg.Warmup.D(),
		Duration:          cfg.Duration.D(),
		UploadDuration:    cfg.UploadDuration.D(),
		MaxDownloadBytes:  cfg.MaxDownloadBytes,
		MaxUploadBytes:    cfg.MaxUploadBytes,
		LightweightBytes:  cfg.LightweightBytes,
		UploadEnabled:     cfg.UploadEnabled,
		Timeout:           cfg.Timeout.D(),
		ExpectedDownload:  cfg.ExpectedDownloadMbps,
		ExpectedUpload:    cfg.ExpectedUploadMbps,
	})
	if err != nil {
		return nil, err
	}
	return &speedMonitor{
		a: a, engine: engine, self: self,
		dlShortfall: a.newGate(),
		ulShortfall: a.newGate(),
	}, nil
}

func (m *speedMonitor) Name() string { return "speedtest" }

func (m *speedMonitor) Tasks() []Task {
	cfg := m.a.cfg
	return []Task{
		{
			Name:         "speedtest-full",
			Interval:     cfg.SpeedTest.FullInterval.D(),
			Timeout:      cfg.SpeedTest.Timeout.D() + 30*time.Second,
			Jitter:       30 * time.Second,
			InitialDelay: cfg.Service.StartupGrace.D(),
			RunOnStart:   true,
			Fn:           func(ctx context.Context) error { return m.run(ctx, speedtest.ModeFull) },
		},
		{
			// Manual full test: the operator asked for it, so the busy-link check does
			// not apply.
			Name:       "speedtest-manual",
			ManualOnly: true,
			Timeout:    cfg.SpeedTest.Timeout.D() + 30*time.Second,
			Fn: func(ctx context.Context) error {
				_, err := m.RunManual(ctx)
				return err
			},
		},
		{
			Name:         "speedtest-light",
			Interval:     cfg.SpeedTest.LightweightInterval.D(),
			Timeout:      60 * time.Second,
			Jitter:       cfg.Monitoring.Jitter.D(),
			InitialDelay: 20 * time.Second,
			RunOnStart:   true,
			Fn:           func(ctx context.Context) error { return m.run(ctx, speedtest.ModeLightweight) },
		},
	}
}

// run performs one test, unless there is a good reason not to.
func (m *speedMonitor) run(ctx context.Context, mode speedtest.Mode) error {
	if reason, skip := m.shouldSkip(mode); skip {
		m.a.log.Emit(events.New(events.SpeedTestSkippedBusy).
			WithField("Reason", reason).
			WithField("Mode", string(mode)).
			WithFields(events.Fields{}.AddUnit("ObservedMbps", m.currentLinkMbps(), "Mbps")))
		return nil
	}

	endpointName := ""
	if ep, ok := m.engine.SelectedEndpoint(); ok {
		endpointName = ep.Name
	}
	m.a.log.Emit(events.New(events.SpeedTestStarted).
		WithField("Mode", string(mode)).
		WithField("Provider", m.a.cfg.SpeedTest.Provider).
		WithField("TestServer", endpointName))

	res, runErr := m.engine.Run(ctx, mode)

	// Attribute the bytes to iPulse whatever the outcome: a failed test still moved
	// data, and the traffic monitor must not read it as an anomaly.
	if m.self != nil && !res.Started.IsZero() {
		rx, tx := res.TotalBytes()
		finished := res.Finished
		if finished.IsZero() {
			finished = time.Now()
		}
		m.self.Record(res.Started, finished, rx, tx, "speedtest-"+string(mode))
	}

	if runErr != nil {
		attempts := 1
		m.a.log.Emit(events.New(events.SpeedTestFailed).
			WithField("Mode", string(mode)).
			WithField("Provider", res.Provider).
			WithField("TestServer", res.Endpoint.Name).
			WithField("Error", runErr).
			WithField("Attempts", attempts))
		m.reportUnavailableEndpoints(ctx)
		// Store the failure so the history shows the gap and its reason.
		if _, err := m.a.db.InsertSpeedTest(ctx, m.record(res, mode)); err != nil {
			return err
		}
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			return nil
		}
		return nil
	}

	if _, err := m.a.db.InsertSpeedTest(ctx, m.record(res, mode)); err != nil {
		return err
	}
	if err := m.storeMeasurements(ctx, res, mode); err != nil {
		return err
	}
	m.updateState(res, mode)
	m.emitCompleted(res, mode)

	if mode != speedtest.ModeLightweight {
		m.checkISPExpectations(ctx, res)
	}
	return nil
}

// shouldSkip decides whether running now would be wasteful or misleading.
func (m *speedMonitor) shouldSkip(mode speedtest.Mode) (string, bool) {
	if !m.a.cfg.SpeedTest.Enabled {
		return "speed testing is disabled in configuration", true
	}
	if !m.a.state.Online() {
		return "the connection is down", true
	}
	if m.engine.Running() {
		return "a speed test is already running", true
	}
	// Measuring a link that is already busy produces a number that describes the other
	// traffic, not the link, and competes with the user's own transfer.
	if limit := m.a.cfg.SpeedTest.SkipIfBusyMbps; limit > 0 && mode != speedtest.ModeManual {
		if busy := m.currentLinkMbps(); busy > limit {
			return fmt.Sprintf("the link is carrying %.1f Mbps, above the %.1f Mbps skip threshold", busy, limit), true
		}
	}
	return "", false
}

// currentLinkMbps is the larger of the current receive and transmit rates, excluding
// iPulse's own traffic.
func (m *speedMonitor) currentLinkMbps() float64 {
	snap := m.a.state.Snapshot()
	rx := snap.RxBps / 1e6
	tx := snap.TxBps / 1e6
	if tx > rx {
		return tx
	}
	return rx
}

func (m *speedMonitor) record(res speedtest.Result, mode speedtest.Mode) database.SpeedTest {
	snap := m.a.state.Snapshot()
	return database.SpeedTest{
		Time:             res.Time,
		Mode:             string(mode),
		Provider:         res.Provider,
		Endpoint:         res.Endpoint.Name,
		EndpointLocation: res.Endpoint.Location,
		DownloadMbps:     res.Download.Mbps,
		UploadMbps:       res.Upload.Mbps,
		DownloadP90Mbps:  res.Download.P90Mbps,
		UploadP90Mbps:    res.Upload.P90Mbps,
		LatencyMS:        msOf(res.Latency.RTT),
		JitterMS:         msOf(res.Latency.Jitter),
		PacketLossPct:    res.Latency.LossPct,
		TCPConnectMS:     msOf(res.Latency.TCPConnect),
		DNSMS:            msOf(res.Latency.DNS),
		TTFBMS:           msOf(res.Latency.TTFB),
		BytesDown:        res.Download.Bytes,
		BytesUp:          res.Upload.Bytes,
		Streams:          res.Download.Streams,
		Duration:         res.Duration,
		Status:           res.Status,
		Error:            res.Error,
		ExpectedDownload: m.a.cfg.SpeedTest.ExpectedDownloadMbps,
		ExpectedUpload:   m.a.cfg.SpeedTest.ExpectedUploadMbps,
		Interface:        snap.Interface,
		PublicIP:         snap.PublicIPv4,
		ISP:              snap.ISP,
		Raw:              res.Raw(),
	}
}

func (m *speedMonitor) storeMeasurements(ctx context.Context, res speedtest.Result, mode speedtest.Mode) error {
	now := res.Time
	var ms []database.Measurement

	if mode == speedtest.ModeLightweight {
		ms = append(ms, database.Measurement{
			Time: now, Metric: database.MetricLightDownMbps, Value: res.Download.Mbps,
			Unit: "Mbps", Target: res.Endpoint.Name, OK: true,
		})
	} else {
		if res.Download.Mbps > 0 {
			ms = append(ms, database.Measurement{
				Time: now, Metric: database.MetricDownloadMbps, Value: res.Download.Mbps,
				Unit: "Mbps", Target: res.Endpoint.Name, OK: true,
			})
		}
		if res.Upload.Mbps > 0 {
			ms = append(ms, database.Measurement{
				Time: now, Metric: database.MetricUploadMbps, Value: res.Upload.Mbps,
				Unit: "Mbps", Target: res.Endpoint.Name, OK: true,
			})
		}
	}
	if res.Latency.TCPConnect > 0 {
		ms = append(ms, database.Measurement{
			Time: now, Metric: database.MetricTCPConnectMS, Value: msOf(res.Latency.TCPConnect),
			Unit: "ms", Target: res.Endpoint.Name, OK: true,
		})
	}
	if res.Latency.TTFB > 0 {
		ms = append(ms, database.Measurement{
			Time: now, Metric: database.MetricHTTPSTTFBMS, Value: msOf(res.Latency.TTFB),
			Unit: "ms", Target: res.Endpoint.Name, OK: true,
		})
	}
	if err := m.a.db.InsertMeasurements(ctx, ms); err != nil {
		return err
	}

	// Publish to the analysis pipeline. Lightweight and full results are separate
	// metrics: they measure different things and must not share a baseline.
	if mode == speedtest.ModeLightweight {
		m.a.publishSamples(now, sample{
			Metric: database.MetricLightDownMbps, Value: res.Download.Mbps, Valid: res.Download.Mbps > 0,
		})
	} else {
		m.a.publishSamples(now,
			sample{Metric: database.MetricDownloadMbps, Value: res.Download.Mbps, Valid: res.Download.Mbps > 0},
			sample{Metric: database.MetricUploadMbps, Value: res.Upload.Mbps, Valid: res.Upload.Mbps > 0},
		)
	}
	return nil
}

func (m *speedMonitor) updateState(res speedtest.Result, mode speedtest.Mode) {
	m.a.state.Update(func(s *Snapshot) {
		if mode == speedtest.ModeLightweight {
			s.EstimatedDownloadMbps = res.Download.Mbps
			return
		}
		s.DownloadMbps = res.Download.Mbps
		if res.Upload.Mbps > 0 {
			s.UploadMbps = res.Upload.Mbps
		}
		s.LastSpeedTest = res.Time
		s.LastSpeedTestServer = res.Endpoint.Name
		if res.Latency.RTT > 0 && s.LatencyMS == 0 {
			s.LatencyMS = msOf(res.Latency.RTT)
		}
	})
}

func (m *speedMonitor) emitCompleted(res speedtest.Result, mode speedtest.Mode) {
	if mode == speedtest.ModeLightweight {
		m.a.log.Emit(events.New(events.ThroughputSample).
			WithFields(events.Fields{}.
				AddUnit("Download", res.Download.Mbps, "Mbps").
				AddUnit("Latency", msOf(res.Latency.RTT), "ms").
				AddBytes("Bytes", float64(res.Download.Bytes)).
				AddDuration("Duration", res.Duration).
				Add("TestServer", res.Endpoint.Name)))
		return
	}

	status := m.classify(res)
	fields := events.Fields{}.
		AddUnit("Download", res.Download.Mbps, "Mbps").
		AddUnit("Upload", res.Upload.Mbps, "Mbps").
		AddUnit("Latency", msOf(res.Latency.RTT), "ms").
		AddUnit("Jitter", msOf(res.Latency.Jitter), "ms").
		AddPercent("PacketLoss", res.Latency.LossPct).
		Add("Status", status).
		Add("TestServer", res.Endpoint.Name).
		AddDuration("Duration", res.Duration).
		Add("Mode", string(mode)).
		AddBytes("BytesDown", float64(res.Download.Bytes)).
		AddBytes("BytesUp", float64(res.Upload.Bytes)).
		Add("Streams", res.Download.Streams)

	if res.Download.P90Mbps > 0 {
		fields = fields.AddUnit("DownloadP90", res.Download.P90Mbps, "Mbps")
	}
	if res.Download.Capped {
		fields = fields.Add("DownloadCapped", true)
	}
	if res.Status == speedtest.StatusPartial {
		fields = fields.Add("Warning", res.Error)
	}
	m.a.log.Emit(events.New(events.SpeedTestCompleted).WithFields(fields))
}

// classify labels a result against the configured ISP expectation, which is the only
// absolute reference iPulse has for "is this fast enough".
func (m *speedMonitor) classify(res speedtest.Result) string {
	cfg := m.a.cfg
	expectedDL := cfg.SpeedTest.ExpectedDownloadMbps
	expectedUL := cfg.SpeedTest.ExpectedUploadMbps
	shortfall := cfg.Alerts.ISPShortfallPercent

	if expectedDL <= 0 && expectedUL <= 0 {
		return "MEASURED"
	}
	degraded := false
	if expectedDL > 0 && res.Download.Mbps < expectedDL*(1-shortfall/100) {
		degraded = true
	}
	if expectedUL > 0 && res.Upload.Mbps > 0 && res.Upload.Mbps < expectedUL*(1-shortfall/100) {
		degraded = true
	}
	if degraded {
		return "DEGRADED"
	}
	return "HEALTHY"
}

// checkISPExpectations reports sustained shortfall against the advertised plan. It uses
// the recent history rather than a single test, because one slow test is not evidence
// worth taking to an ISP.
func (m *speedMonitor) checkISPExpectations(ctx context.Context, res speedtest.Result) {
	cfg := m.a.cfg
	shortfall := cfg.Alerts.ISPShortfallPercent
	now := res.Time
	window := 24 * time.Hour

	if expected := cfg.SpeedTest.ExpectedDownloadMbps; expected > 0 && res.Download.Mbps > 0 {
		threshold := expected * (1 - shortfall/100)
		d := m.dlShortfall.Observe("isp-download", res.Download.Mbps < threshold, now)
		if d.Fire {
			values, _ := m.a.db.MetricValues(ctx, database.MetricDownloadMbps, "", now.Add(-window), now)
			m.a.log.Emit(events.New(events.DownloadBelowISPExpected).
				WithFields(events.Fields{}.
					AddUnit("ExpectedDownload", expected, "Mbps").
					AddUnit("MeasuredDownload", res.Download.Mbps, "Mbps").
					AddRatioPercent("Shortfall", (expected-res.Download.Mbps)/expected*100).
					Add("TestServer", res.Endpoint.Name).
					AddPercent("SamplesBelow", util.PercentBelow(values, threshold)).
					Add("SampleWindow", "24h").
					Add("Consecutive", d.Consecutive)))
		}
	}

	if expected := cfg.SpeedTest.ExpectedUploadMbps; expected > 0 && res.Upload.Mbps > 0 {
		threshold := expected * (1 - shortfall/100)
		d := m.ulShortfall.Observe("isp-upload", res.Upload.Mbps < threshold, now)
		if d.Fire {
			values, _ := m.a.db.MetricValues(ctx, database.MetricUploadMbps, "", now.Add(-window), now)
			m.a.log.Emit(events.New(events.UploadBelowISPExpected).
				WithFields(events.Fields{}.
					AddUnit("ExpectedUpload", expected, "Mbps").
					AddUnit("MeasuredUpload", res.Upload.Mbps, "Mbps").
					AddRatioPercent("Shortfall", (expected-res.Upload.Mbps)/expected*100).
					Add("TestServer", res.Endpoint.Name).
					AddPercent("SamplesBelow", util.PercentBelow(values, threshold)).
					Add("SampleWindow", "24h").
					Add("Consecutive", d.Consecutive)))
		}
	}
}

// reportUnavailableEndpoints names the endpoints that could not be reached, so an
// operator can fix or remove them instead of seeing only a generic failure.
func (m *speedMonitor) reportUnavailableEndpoints(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for name, reason := range m.engine.UnavailableEndpoints(probeCtx) {
		m.a.once("speed-endpoint-"+name, func() {
			m.a.log.Emit(events.New(events.SpeedEndpointUnavailable).
				WithField("Endpoint", name).
				WithField("Error", reason))
		})
	}
}

// RunManual performs a full test on request, bypassing the busy-link check because the
// operator explicitly asked for it.
func (m *speedMonitor) RunManual(ctx context.Context) (speedtest.Result, error) {
	res, err := m.engine.Run(ctx, speedtest.ModeManual)
	if m.self != nil && !res.Started.IsZero() {
		rx, tx := res.TotalBytes()
		finished := res.Finished
		if finished.IsZero() {
			finished = time.Now()
		}
		m.self.Record(res.Started, finished, rx, tx, "speedtest-manual")
	}
	if err != nil {
		return res, err
	}
	if _, dbErr := m.a.db.InsertSpeedTest(ctx, m.record(res, speedtest.ModeManual)); dbErr != nil {
		return res, dbErr
	}
	if err := m.storeMeasurements(ctx, res, speedtest.ModeManual); err != nil {
		return res, err
	}
	m.updateState(res, speedtest.ModeManual)
	m.emitCompleted(res, speedtest.ModeManual)
	m.checkISPExpectations(ctx, res)
	return res, nil
}
