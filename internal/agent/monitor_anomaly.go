package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/anomaly"
	"github.com/ipulse/ipulse/internal/baseline"
	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/network"
	"github.com/ipulse/ipulse/internal/traffic"
)

// anomalyMonitor is the detection pipeline: it maintains the baselines and evaluates the
// deviation rules against every sample the collectors publish.
//
// Everything here is deterministic. A sample is folded into its time bucket, compared
// against the history that existed before it, and reported only if the deviation
// persists. Given the same sequence of samples the same events are produced, which is
// what makes the detection logic reviewable and what the simulation tests rely on.
type anomalyMonitor struct {
	a  *Agent
	bl *baseline.Engine

	// Deviation rules, keyed by metric.
	deviation map[string]*anomaly.DeviationRule
	zscore    map[string]*anomaly.ZScoreRule

	// Sustained conditions.
	sustainedUpload    *anomaly.SustainedRule
	sustainedDownload  *anomaly.SustainedRule
	sustainedUploadBps *anomaly.SustainedRule

	quietHours anomaly.QuietHours
	// spikePattern recognises regularly repeating spikes, which are usually scheduled
	// work rather than a problem.
	spikePattern map[string]*traffic.PeriodDetector

	largeTransferGate *gate
	volumeGate        *gate

	// lastConnections is the most recent connection snapshot, used to name the process
	// and destination most likely responsible for a traffic anomaly.
	lastConnections network.Snapshot
}

func newAnomalyMonitor(a *Agent) *anomalyMonitor {
	cfg := a.cfg
	bl := baseline.New(baseline.Config{
		MinObservations: cfg.Baseline.MinObservations,
		TimeBuckets:     cfg.Baseline.TimeBuckets,
		BucketHours:     cfg.Baseline.BucketHours,
		EWMAAlpha:       cfg.Baseline.EWMAAlpha,
		WindowSize:      cfg.Baseline.ReservoirSize,
		MaxAge:          cfg.Baseline.MaxSampleAge.D(),
	})

	m := &anomalyMonitor{
		a:                 a,
		bl:                bl,
		deviation:         map[string]*anomaly.DeviationRule{},
		zscore:            map[string]*anomaly.ZScoreRule{},
		spikePattern:      map[string]*traffic.PeriodDetector{},
		largeTransferGate: a.newGate(),
		volumeGate:        a.newGate(),
		quietHours: anomaly.QuietHours{
			Start: cfg.Traffic.QuietHoursStart,
			End:   cfg.Traffic.QuietHoursEnd,
		},
	}

	alerts := cfg.Alerts
	// Quality metrics: larger is worse, compared against the median because occasional
	// spikes are normal and should not move the reference.
	m.deviation[database.MetricLatencyMS] = anomaly.NewDeviationRule(
		database.MetricLatencyMS, anomaly.Above, alerts.LatencyDegradationPercent,
		alerts.MinAbsoluteLatencyMS, true, a.newGate())
	m.deviation[database.MetricJitterMS] = anomaly.NewDeviationRule(
		database.MetricJitterMS, anomaly.Above, alerts.JitterDegradationPercent,
		2, true, a.newGate())
	m.deviation[database.MetricDNSMS] = anomaly.NewDeviationRule(
		database.MetricDNSMS, anomaly.Above, alerts.DNSDegradationPercent,
		50, true, a.newGate())

	// Throughput: smaller is worse.
	m.deviation[database.MetricDownloadMbps] = anomaly.NewDeviationRule(
		database.MetricDownloadMbps, anomaly.Below, alerts.DownloadDegradationPercent,
		alerts.MinAbsoluteMbps, true, a.newGate())
	m.deviation[database.MetricUploadMbps] = anomaly.NewDeviationRule(
		database.MetricUploadMbps, anomaly.Below, alerts.UploadDegradationPercent,
		alerts.MinAbsoluteMbps, true, a.newGate())
	m.deviation[database.MetricLightDownMbps] = anomaly.NewDeviationRule(
		database.MetricLightDownMbps, anomaly.Below, alerts.DownloadDegradationPercent,
		alerts.MinAbsoluteMbps, true, a.newGate())
	m.deviation[database.MetricWiFiLinkMbps] = anomaly.NewDeviationRule(
		database.MetricWiFiLinkMbps, anomaly.Below, cfg.WiFi.LinkSpeedDegradePercent,
		1, true, a.newGate())

	// Traffic and counts: robust z-score, because these distributions are skewed.
	spikeFloorBps := cfg.Traffic.SpikeMinMbps * 1e6
	m.zscore[database.MetricRxBps] = anomaly.NewZScoreRule(
		database.MetricRxBps, cfg.Traffic.SpikeZScore, spikeFloorBps, anomaly.Above, a.newGate())
	m.zscore[database.MetricTxBps] = anomaly.NewZScoreRule(
		database.MetricTxBps, cfg.Traffic.SpikeZScore, spikeFloorBps, anomaly.Above, a.newGate())
	m.zscore[database.MetricConnCount] = anomaly.NewZScoreRule(
		database.MetricConnCount, cfg.Traffic.SpikeZScore, 10, anomaly.Above, a.newGate())
	// Volume over a window, which is what "unexpected upload" really means.
	volumeFloor := cfg.Destinations.HighVolumeMB * 1024 * 1024
	m.zscore[database.MetricTxBytesWindow] = anomaly.NewZScoreRule(
		database.MetricTxBytesWindow, cfg.Traffic.SpikeZScore, volumeFloor, anomaly.Above, a.newGate())
	m.zscore[database.MetricRxBytesWindow] = anomaly.NewZScoreRule(
		database.MetricRxBytesWindow, cfg.Traffic.SpikeZScore, volumeFloor, anomaly.Above, a.newGate())

	// Sustained conditions.
	m.sustainedUpload = anomaly.NewSustainedRule(database.MetricTxBps,
		cfg.Traffic.SustainedUploadMbps*1e6,
		time.Duration(alerts.SustainedUploadSeconds)*time.Second, 30*time.Minute)
	m.sustainedDownload = anomaly.NewSustainedRule(database.MetricRxBps,
		spikeFloorBps, time.Duration(cfg.Traffic.SustainedSeconds)*time.Second, time.Hour)
	m.sustainedUploadBps = anomaly.NewSustainedRule("tx_bps_sustained",
		spikeFloorBps, time.Duration(cfg.Traffic.SustainedSeconds)*time.Second, time.Hour)

	return m
}

func (m *anomalyMonitor) Name() string { return "anomaly" }

func (m *anomalyMonitor) Tasks() []Task {
	return []Task{
		{
			Name:         "baseline-flush",
			Interval:     m.a.cfg.Monitoring.BaselineFlushInterval.D(),
			Timeout:      time.Minute,
			InitialDelay: time.Minute,
			Fn:           m.flush,
		},
	}
}

// Baselines exposes the engine for the API.
func (m *anomalyMonitor) Baselines() *baseline.Engine { return m.bl }

// Restore loads persisted baselines so a restart keeps its learned history.
func (m *anomalyMonitor) Restore(ctx context.Context) error {
	rows, err := m.a.db.LoadBaselines(ctx)
	if err != nil {
		return err
	}
	converted := make([]baseline.Row, 0, len(rows))
	for _, r := range rows {
		converted = append(converted, baseline.Row{
			Metric: r.Metric, Dimension: r.Dimension, Bucket: r.Bucket, Samples: r.Samples,
			Mean: r.Mean, M2: r.M2, Min: r.Min, Max: r.Max, EWMA: r.EWMA,
			Median: r.Median, MAD: r.MAD, P10: r.P10, P25: r.P25, P75: r.P75,
			P90: r.P90, P95: r.P95, P99: r.P99, Window: r.Reservoir,
			Established: r.Established, FirstSeen: r.FirstSeen, UpdatedAt: r.UpdatedAt,
		})
	}
	m.bl.Load(converted)
	total, established := m.bl.Count()
	if total > 0 {
		m.a.log.Emit(events.New(events.BaselineEstablished).
			WithField("Metric", "(restored)").
			WithField("Bucket", "(all)").
			WithField("Observations", total).
			WithField("Detail", fmt.Sprintf("%d baselines restored, %d usable", total, established)))
	}
	return nil
}

// flush persists changed baselines and prunes stale ones.
func (m *anomalyMonitor) flush(ctx context.Context) error {
	rows := m.bl.TakeDirty()
	if len(rows) > 0 {
		converted := make([]database.BaselineRow, 0, len(rows))
		for _, r := range rows {
			converted = append(converted, database.BaselineRow{
				Metric: r.Metric, Dimension: r.Dimension, Bucket: r.Bucket, Samples: r.Samples,
				Mean: r.Mean, M2: r.M2, Min: r.Min, Max: r.Max, EWMA: r.EWMA,
				Median: r.Median, MAD: r.MAD, P10: r.P10, P25: r.P25, P75: r.P75,
				P90: r.P90, P95: r.P95, P99: r.P99, Reservoir: r.Window,
				Established: r.Established, FirstSeen: r.FirstSeen, UpdatedAt: r.UpdatedAt,
			})
		}
		if err := m.a.db.SaveBaselines(ctx, converted); err != nil {
			return err
		}
	}
	m.bl.Prune(time.Now())
	return nil
}

// Connections implements connectionConsumer: the snapshot is kept so traffic anomalies
// can name the process and destination most likely responsible.
func (m *anomalyMonitor) Connections(_ context.Context, snap network.Snapshot) error {
	m.lastConnections = snap
	return nil
}

// Samples implements sampleConsumer. This is the whole detection pipeline: fold each
// sample into its baseline, then evaluate the rules for that metric.
func (m *anomalyMonitor) Samples(ctx context.Context, batch []sample) {
	for _, s := range batch {
		if !s.Valid {
			continue
		}
		prior, established := m.bl.Observe(s.Metric, s.Target, s.Value, s.Time)
		if established {
			m.reportEstablished(prior, s)
		}

		// Prefer the time-bucketed baseline, falling back to the aggregate so detection
		// works from the first hours rather than waiting for every bucket to fill.
		reference := prior
		if !reference.Usable() {
			if best, ok := m.bl.Best(s.Metric, s.Target, s.Time); ok {
				reference = best
			}
		}

		if rule, ok := m.deviation[s.Metric]; ok {
			if f, fired := rule.Evaluate(reference, s.Value, s.Target, s.Time); fired {
				m.reportDeviation(ctx, s, f)
			}
		}
		if rule, ok := m.zscore[s.Metric]; ok {
			if f, fired := rule.Evaluate(reference, s.Value, s.Target, s.Time); fired {
				m.reportZScore(ctx, s, f)
			}
		}
		m.evaluateSustained(s)
	}
}

func (m *anomalyMonitor) reportEstablished(b baseline.Baseline, s sample) {
	ev := events.New(events.BaselineEstablished).
		WithField("Metric", s.Metric).
		WithField("Bucket", m.bl.BucketFor(s.Time)).
		WithField("Observations", b.Samples+1).
		WithFields(events.Fields{}.
			AddUnitPrec("Mean", b.Mean, "", 3).
			AddUnitPrec("Median", b.Median, "", 3).
			AddUnitPrec("P95", b.P95, "", 3).
			AddUnitPrec("StdDev", b.StdDev(), "", 3))
	if s.Target != "" {
		ev = ev.WithField("Dimension", s.Target)
	}
	m.a.log.Emit(ev)
}

// reportDeviation maps a deviation finding onto its catalogued event, adding the context
// that makes the finding actionable rather than merely true.
func (m *anomalyMonitor) reportDeviation(ctx context.Context, s sample, f anomaly.Finding) {
	snap := m.a.state.Snapshot()
	common := events.Fields{}.
		AddRatioPercent("Deviation", f.DeviationPct).
		Add("Bucket", f.Bucket).
		Add("Observations", f.Observations)
	if s.Target != "" {
		common = common.Add("Target", s.Target)
	}

	switch s.Metric {
	case database.MetricLatencyMS:
		if f.Recovered {
			m.emitRecovery("latency", f, s)
			return
		}
		// Latency degradation is only useful with the context that explains it: is the
		// link saturated, is the local hop slow, is there loss?
		cause, util := m.latencyContext(snap)
		m.a.log.Emit(events.New(events.LatencyDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineLatency", f.Baseline, "ms").
				AddUnit("CurrentLatency", f.Value, "ms")).
			WithFields(common).
			WithFields(events.Fields{}.
				AddPercent("PacketLoss", snap.PacketLossPct).
				AddRatioPercent("UploadUtilization", util.upload).
				AddRatioPercent("DownloadUtilization", util.download).
				AddUnit("GatewayRTT", snap.GatewayRTTMS, "ms").
				Add("ProbableCause", cause)))

	case database.MetricJitterMS:
		if f.Recovered {
			m.emitRecovery("jitter", f, s)
			return
		}
		m.a.log.Emit(events.New(events.JitterDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineJitter", f.Baseline, "ms").
				AddUnit("CurrentJitter", f.Value, "ms")).
			WithFields(common).
			WithFields(events.Fields{}.AddPercent("PacketLoss", snap.PacketLossPct)))

	case database.MetricDNSMS:
		if f.Recovered {
			m.emitRecovery("dns", f, s)
			return
		}
		m.a.log.Emit(events.New(events.DNSResponseDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineDNS", f.Baseline, "ms").
				AddUnit("CurrentDNS", f.Value, "ms")).
			WithFields(common).
			WithField("Server", s.Target))

	case database.MetricDownloadMbps:
		if f.Recovered {
			m.emitRecovery("download", f, s)
			return
		}
		m.a.log.Emit(events.New(events.DownloadDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineDownload", f.Baseline, "Mbps").
				AddUnit("CurrentDownload", f.Value, "Mbps")).
			WithFields(common).
			WithField("ProbableCause", m.throughputCause(snap)))

	case database.MetricUploadMbps:
		if f.Recovered {
			m.emitRecovery("upload", f, s)
			return
		}
		m.a.log.Emit(events.New(events.UploadDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineUpload", f.Baseline, "Mbps").
				AddUnit("CurrentUpload", f.Value, "Mbps")).
			WithFields(common).
			WithField("ProbableCause", m.throughputCause(snap)))

	case database.MetricLightDownMbps:
		if f.Recovered {
			return // the full-test recovery is the meaningful one
		}
		m.a.log.Emit(events.New(events.ThroughputDegradation).
			WithFields(events.Fields{}.
				AddUnit("BaselineDownload", f.Baseline, "Mbps").
				AddUnit("CurrentDownload", f.Value, "Mbps")).
			WithFields(common).
			WithField("Consecutive", f.Consecutive))

	case database.MetricWiFiLinkMbps:
		if f.Recovered {
			return
		}
		m.a.log.Emit(events.New(events.WiFiLinkSpeedDegraded).
			WithField("Interface", s.Target).
			WithField("SSID", wifiSSID(snap)).
			WithFields(events.Fields{}.
				AddUnit("LinkSpeed", f.Value, "Mbps").
				AddUnit("BaselineLinkSpeed", f.Baseline, "Mbps")).
			WithFields(common).
			WithField("Signal", signalField(wifiSignal(snap))))
	}
}

// reportZScore maps a robust-deviation finding onto its event.
func (m *anomalyMonitor) reportZScore(ctx context.Context, s sample, f anomaly.Finding) {
	if f.Recovered {
		return // spikes are instantaneous; a recovery event would add nothing
	}
	topProcess, topDest := m.topContributors()
	common := events.Fields{}.
		Add("Interface", s.Target).
		AddRatioPercent("Deviation", f.DeviationPct).
		AddUnitPrec("ZScore", f.ZScore, "", 1).
		Add("Bucket", f.Bucket).
		Add("Observations", f.Observations)
	if topProcess != "" {
		common = common.Add("TopProcess", topProcess)
	}

	switch s.Metric {
	case database.MetricRxBps:
		m.recordSpike("rx:"+s.Target, s.Time)
		m.a.log.Emit(events.New(events.BandwidthSpikeDownload).
			WithFields(events.Fields{}.
				AddRate("CurrentRate", f.Value).
				AddRate("BaselineRate", f.Baseline)).
			WithFields(common))
		m.reportPeriodic("rx:"+s.Target, "download", s, f)

	case database.MetricTxBps:
		m.recordSpike("tx:"+s.Target, s.Time)
		fields := common
		if topDest != "" {
			fields = fields.Add("TopDestination", topDest)
		}
		m.a.log.Emit(events.New(events.BandwidthSpikeUpload).
			WithFields(events.Fields{}.
				AddRate("CurrentRate", f.Value).
				AddRate("BaselineRate", f.Baseline)).
			WithFields(fields))
		m.reportPeriodic("tx:"+s.Target, "upload", s, f)

	case database.MetricConnCount:
		m.a.log.Emit(events.New(events.ConnectionCountAnomaly).
			WithFields(events.Fields{}.
				AddUnitPrec("Current", f.Value, "", 0).
				AddUnitPrec("BaselineMedian", f.Baseline, "", 0)).
			WithFields(common))

	case database.MetricTxBytesWindow:
		m.reportOutboundVolume(s, f, topProcess, topDest)

	case database.MetricRxBytesWindow:
		// Inbound volume during a normally quiet period is worth noting; otherwise the
		// rate spike already covered it.
		if m.quietHours.Contains(s.Time) {
			m.a.log.Emit(events.New(events.UnusualOvernightTraffic).
				WithField("Window", m.quietHours.Describe()).
				WithField("Direction", "download").
				WithFields(events.Fields{}.
					AddBytes("Bytes", f.Value).
					AddBytes("BaselineBytes", f.Baseline)).
				WithFields(common))
		}
	}
}

// reportOutboundVolume is the unexpected-upload detector: volume over a window, compared
// against the same window in the same time bucket.
func (m *anomalyMonitor) reportOutboundVolume(s sample, f anomaly.Finding, topProcess, topDest string) {
	fields := events.Fields{}.
		Add("Interface", s.Target).
		AddBytes("WindowBytes", f.Value).
		AddBytes("BaselineBytes", f.Baseline).
		AddRatioPercent("Deviation", f.DeviationPct).
		Add("Bucket", f.Bucket).
		Add("Observations", f.Observations)
	if topProcess != "" {
		fields = fields.Add("TopProcess", topProcess)
	}
	if topDest != "" {
		fields = fields.Add("TopDestination", topDest)
	}
	// Attribution is by concurrency, not by per-flow accounting: neither Linux nor
	// Windows exposes per-process network byte counters without packet capture, which
	// iPulse does not do. Saying so keeps the event honest.
	fields = fields.
		Add("Attribution", "concurrency-based: the process and destination most active during the window").
		Add("Confidence", "low")

	if m.quietHours.Contains(s.Time) {
		m.a.log.Emit(events.New(events.UnusualOvernightTraffic).
			WithField("Window", m.quietHours.Describe()).
			WithField("Direction", "upload").
			WithFields(fields))
		return
	}
	m.a.log.Emit(events.New(events.UnusualOutboundTraffic).WithFields(fields))

	// A very large window volume is also reported as a large transfer, which is the
	// event an operator is likely to alert on.
	if threshold := m.a.cfg.Traffic.LargeTransferMB * 1024 * 1024; threshold > 0 && f.Value >= threshold {
		if d := m.largeTransferGate.Observe("large-transfer:"+s.Target, true, s.Time); d.Fire {
			m.a.log.Emit(events.New(events.LargeOutboundTransfer).
				WithField("Destination", topDest).
				WithFields(events.Fields{}.AddBytes("BytesSent", f.Value)).
				WithField("Duration", m.volumeWindowFor()).
				WithField("Process", topProcess).
				WithField("Interface", s.Target).
				WithField("Attribution", "concurrency-based: no per-process byte accounting is available without packet capture").
				WithField("Confidence", "low"))
		}
	}
}

// evaluateSustained applies the sustained-condition rules.
func (m *anomalyMonitor) evaluateSustained(s sample) {
	switch s.Metric {
	case database.MetricTxBps:
		if f, ok := m.sustainedUpload.Observe(s.Target, s.Value, s.Time); ok && !f.Ended {
			topProcess, topDest := m.topContributors()
			m.a.log.Emit(events.New(events.SustainedUpload).
				WithField("Interface", s.Target).
				WithFields(events.Fields{}.
					AddRate("AverageRate", f.Average).
					AddRate("PeakRate", f.Peak).
					AddDuration("Duration", f.Duration).
					AddBytes("BytesSent", f.Average*f.Duration.Seconds()/8)).
				WithField("TopProcess", topProcess).
				WithField("TopDestination", topDest).
				WithField("Samples", f.Samples).
				WithField("Confidence", "medium"))
		}
		if f, ok := m.sustainedUploadBps.Observe(s.Target, s.Value, s.Time); ok && !f.Ended {
			m.emitSustainedBandwidth(s, f, "upload")
		}
	case database.MetricRxBps:
		if f, ok := m.sustainedDownload.Observe(s.Target, s.Value, s.Time); ok && !f.Ended {
			m.emitSustainedBandwidth(s, f, "download")
		}
	}
}

func (m *anomalyMonitor) emitSustainedBandwidth(s sample, f anomaly.SustainedFinding, direction string) {
	topProcess, _ := m.topContributors()
	m.a.log.Emit(events.New(events.SustainedBandwidthUsage).
		WithField("Interface", s.Target).
		WithField("Direction", direction).
		WithFields(events.Fields{}.
			AddRate("AverageRate", f.Average).
			AddRate("PeakRate", f.Peak).
			AddDuration("Duration", f.Duration).
			AddBytes("BytesTransferred", f.Average*f.Duration.Seconds()/8)).
		WithField("TopProcess", topProcess))
}

// reportPeriodic notes when spikes repeat on a regular schedule, which is usually
// scheduled work and therefore context rather than a problem.
func (m *anomalyMonitor) reportPeriodic(key, direction string, s sample, f anomaly.Finding) {
	det, ok := m.spikePattern[key]
	if !ok {
		return
	}
	period, occurrences, found := det.Period(4, 0.2)
	if !found {
		return
	}
	if d := m.volumeGate.Observe("periodic:"+key, true, s.Time); !d.Fire {
		return
	}
	m.a.log.Emit(events.New(events.PeriodicSpikePattern).
		WithField("Period", period.Round(time.Second)).
		WithField("Occurrences", occurrences).
		WithField("Direction", direction).
		WithFields(events.Fields{}.AddRate("AverageSpike", f.Value)).
		WithField("Interface", s.Target).
		WithField("Detail", "repeating spikes at a regular interval, most likely scheduled activity"))
	det.Reset()
}

func (m *anomalyMonitor) recordSpike(key string, at time.Time) {
	det, ok := m.spikePattern[key]
	if !ok {
		det = traffic.NewPeriodDetector(12)
		m.spikePattern[key] = det
	}
	det.Record(at)
}

// utilisation describes how much of the measured capacity is in use.
type utilisation struct {
	upload   float64
	download float64
}

// latencyContext works out the most likely explanation for a latency rise, which is what
// turns the event from an observation into something actionable.
func (m *anomalyMonitor) latencyContext(snap Snapshot) (string, utilisation) {
	var u utilisation
	if snap.UploadMbps > 0 {
		u.upload = snap.TxBps / (snap.UploadMbps * 1e6) * 100
	}
	if snap.DownloadMbps > 0 {
		u.download = snap.RxBps / (snap.DownloadMbps * 1e6) * 100
	}

	switch {
	case u.upload >= 80:
		return "Outbound bandwidth saturation", u
	case u.download >= 80:
		return "Inbound bandwidth saturation", u
	case snap.WiFi != nil && snap.WiFi.SignalDBM != 0 && snap.WiFi.SignalDBM <= m.a.cfg.WiFi.WeakSignalDBM:
		return "Weak wireless signal", u
	case snap.GatewayRTTMS > 0 && snap.GatewayRTTMS > snap.LatencyMS/2:
		return "Local network or gateway latency", u
	case snap.PacketLossPct >= m.a.cfg.Alerts.PacketLossPercent:
		return "Packet loss on the path", u
	default:
		return "Upstream path latency", u
	}
}

func (m *anomalyMonitor) throughputCause(snap Snapshot) string {
	if snap.TxBps > 0 && snap.UploadMbps > 0 && snap.TxBps/(snap.UploadMbps*1e6) > 0.5 {
		return "Local upload activity during the test"
	}
	if snap.RxBps > 0 && snap.DownloadMbps > 0 && snap.RxBps/(snap.DownloadMbps*1e6) > 0.5 {
		return "Local download activity during the test"
	}
	if snap.WiFi != nil && snap.WiFi.SignalDBM != 0 && snap.WiFi.SignalDBM <= m.a.cfg.WiFi.WeakSignalDBM {
		return "Weak wireless signal"
	}
	return "Upstream or ISP performance"
}

// topContributors names the process and destination most active in the latest connection
// snapshot. This is the best attribution available without packet capture.
func (m *anomalyMonitor) topContributors() (process, destination string) {
	snap := m.lastConnections
	if snap.Total == 0 {
		return "", ""
	}
	process = network.TopProcess(snap)

	counts := map[string]int{}
	for _, c := range snap.Connections {
		if c.Internal || c.RemoteIP == "" {
			continue
		}
		counts[c.RemoteIP]++
	}
	best := 0
	for ip, n := range counts {
		if n > best || (n == best && ip < destination) {
			best, destination = n, ip
		}
	}
	return process, destination
}

func (m *anomalyMonitor) volumeWindowFor() time.Duration { return 5 * time.Minute }

func (m *anomalyMonitor) emitRecovery(metric string, f anomaly.Finding, s sample) {
	m.a.log.Emit(events.New(events.PerformanceRecovered).
		WithField("Metric", metric).
		WithFields(events.Fields{}.
			AddUnitPrec("Current", f.Value, "", 2).
			AddUnitPrec("Baseline", f.Baseline, "", 2)).
		WithField("DegradedFor", f.Duration).
		WithField("Target", s.Target))
}

func wifiSSID(snap Snapshot) string {
	if snap.WiFi == nil {
		return ""
	}
	return snap.WiFi.SSID
}

func wifiSignal(snap Snapshot) int {
	if snap.WiFi == nil {
		return 0
	}
	return snap.WiFi.SignalDBM
}
