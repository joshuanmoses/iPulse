package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/security"
	"github.com/ipulse/ipulse/internal/version"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend.State().Snapshot())
}

// handleHealth is both the health score and a liveness endpoint, so a supervisor can
// probe it without needing to understand the payload.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := s.backend.State().Snapshot()
	cfg := s.backend.Config()
	resp := map[string]any{
		"score":      snap.HealthScore,
		"components": snap.HealthComponents,
		"status":     snap.Status,
		"online":     snap.Online,
		"uptime":     snap.Uptime.String(),
		"version":    version.Version,
		"warn_below": cfg.Health.WarnBelow,
		"weights":    cfg.Health.Weights,
		"scoring": "score = sum(weight_i * component_i) / sum(weight_i); each component is " +
			"scaled 0-100 between the configured good and bad thresholds. See docs/detection-engine.md.",
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSpeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	mode := r.URL.Query().Get("mode")
	limit := queryInt(r, "limit", 50, 1, 1000)
	since := querySince(r, "since", 7*24*time.Hour)

	tests, err := db.QuerySpeedTests(ctx, mode, since, time.Time{}, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	latest, _, _ := db.LatestSpeedTest(ctx, database.SpeedModeFull)
	cfg := s.backend.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"latest":                 latest,
		"tests":                  tests,
		"expected_download_mbps": cfg.SpeedTest.ExpectedDownloadMbps,
		"expected_upload_mbps":   cfg.SpeedTest.ExpectedUploadMbps,
	})
}

// handleSpeedHistory returns the hour/day/week/month analysis the Speed view charts.
func (s *Server) handleSpeedHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	cfg := s.backend.Config()
	now := time.Now()

	windows := []struct {
		name string
		dur  time.Duration
	}{
		{"hour", time.Hour},
		{"day", 24 * time.Hour},
		{"week", 7 * 24 * time.Hour},
		{"month", 30 * 24 * time.Hour},
	}
	out := make(map[string]database.SpeedSummary, len(windows))
	for _, win := range windows {
		sum, err := db.SpeedStats(ctx, win.name, now.Add(-win.dur), now,
			cfg.SpeedTest.ExpectedDownloadMbps, cfg.SpeedTest.ExpectedUploadMbps)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
			return
		}
		out[win.name] = sum
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := database.EventFilter{
		Since:             querySince(r, "since", 24*time.Hour),
		Process:           q.Get("process"),
		Destination:       q.Get("destination"),
		Search:            q.Get("q"),
		Limit:             queryInt(r, "limit", 200, 1, 5000),
		Offset:            queryInt(r, "offset", 0, 0, 1_000_000),
		IncludeSuppressed: q.Get("include_suppressed") == "true",
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = t
		}
	}
	if v := q.Get("severity"); v != "" {
		sev, err := events.ParseSeverity(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_severity", err.Error())
			return
		}
		if q.Get("exact") == "true" {
			f.Severity = &sev
		} else {
			f.MinSeverity = &sev
		}
	}
	for _, raw := range strings.Split(q.Get("code"), ",") {
		if raw = strings.TrimSpace(raw); raw != "" {
			code, err := strconv.Atoi(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_code", "event codes must be numeric")
				return
			}
			f.Codes = append(f.Codes, code)
		}
	}
	for _, raw := range strings.Split(q.Get("category"), ",") {
		if raw = strings.TrimSpace(raw); raw != "" {
			f.Categories = append(f.Categories, raw)
		}
	}
	for _, raw := range strings.Split(q.Get("name"), ",") {
		if raw = strings.TrimSpace(raw); raw != "" {
			f.Names = append(f.Names, raw)
		}
	}

	ctx := r.Context()
	db := s.backend.DB()
	list, err := db.QueryEvents(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	total, _ := db.CountEvents(ctx, f)
	counts, _ := db.SeverityCounts(ctx, f.Since)
	bySeverity := map[string]int64{}
	for sev, n := range counts {
		bySeverity[sev.String()] = n
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":      list,
		"total":       total,
		"by_severity": bySeverity,
	})
}

// handleEventCatalog exposes the event catalog so the dashboard can explain any event it
// displays without shipping a copy of the documentation.
func (s *Server) handleEventCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, events.All())
}

func (s *Server) handleOutages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	since := querySince(r, "since", 30*24*time.Hour)
	list, err := db.QueryOutages(ctx, since, time.Time{}, queryInt(r, "limit", 100, 1, 1000))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	av, err := db.AvailabilitySince(ctx, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	current, open, _ := db.CurrentOutage(ctx)
	resp := map[string]any{"outages": list, "availability": av}
	if open {
		resp["current"] = current
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := database.ConnectionFilter{
		Since:      querySince(r, "since", time.Hour),
		Protocol:   q.Get("protocol"),
		Process:    q.Get("process"),
		RemoteIP:   q.Get("remote_ip"),
		RemotePort: queryInt(r, "remote_port", 0, 0, 65535),
		State:      q.Get("state"),
		Search:     q.Get("q"),
		Limit:      queryInt(r, "limit", 200, 1, 5000),
		Offset:     queryInt(r, "offset", 0, 0, 1_000_000),
	}
	if v := q.Get("internal"); v != "" {
		b := v == "true"
		f.Internal = &b
	}
	ctx := r.Context()
	db := s.backend.DB()
	list, err := db.QueryConnections(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	top, _ := db.TopProcesses(ctx, f.Since, 10)
	writeJSON(w, http.StatusOK, map[string]any{
		"connections":   list,
		"top_processes": top,
		"count":         len(list),
	})
}

func (s *Server) handleDestinations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := database.DestinationFilter{
		Since:   querySince(r, "since", 7*24*time.Hour),
		Search:  q.Get("q"),
		OrderBy: q.Get("order"),
		Limit:   queryInt(r, "limit", 200, 1, 5000),
		Offset:  queryInt(r, "offset", 0, 0, 1_000_000),
	}
	if v := q.Get("internal"); v != "" {
		b := v == "true"
		f.Internal = &b
	}
	if v := q.Get("flagged"); v != "" {
		b := v == "true"
		f.Flagged = &b
	}
	if v := q.Get("new_since"); v != "" {
		f.NewSince = querySince(r, "new_since", 24*time.Hour)
	}
	ctx := r.Context()
	db := s.backend.DB()
	list, err := db.QueryDestinations(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	total, _ := db.DestinationCount(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"destinations": list, "total": total})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	stored, err := db.ListInterfaces(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	wifi, hasWiFi, _ := db.LatestWiFiSample(ctx)
	resp := map[string]any{"interfaces": stored}
	if hasWiFi {
		resp["wifi"] = wifi
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	v4, hasV4, _ := db.LatestPublicIP(ctx, "ipv4")
	v6, hasV6, _ := db.LatestPublicIP(ctx, "ipv6")
	history, err := db.PublicIPHistory(ctx, queryInt(r, "limit", 25, 1, 500))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	resp := map[string]any{"history": history}
	if hasV4 {
		resp["ipv4"] = v4
	}
	if hasV6 {
		resp["ipv6"] = v6
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleConfig returns the effective configuration with secrets redacted.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.backend.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"path":   cfg.Path(),
		"config": cfg.Redacted(),
	})
}

// handleMeasurements returns a bucketed time series for charting.
func (s *Server) handleMeasurements(w http.ResponseWriter, r *http.Request) {
	metric := r.URL.Query().Get("metric")
	if metric == "" {
		writeError(w, http.StatusBadRequest, "missing_metric", "the metric parameter is required")
		return
	}
	since := querySince(r, "since", 6*time.Hour)
	bucket := time.Duration(queryInt(r, "bucket_seconds", 60, 1, 86400)) * time.Second
	target := r.URL.Query().Get("target")

	ctx := r.Context()
	db := s.backend.DB()
	series, err := db.TimeSeries(ctx, metric, target, since, time.Now(), bucket)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	stats, _ := db.MetricStats(ctx, metric, target, since, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{
		"metric": metric, "target": target, "series": series, "stats": stats,
	})
}

// handleTraffic returns interface throughput samples for the Traffic view.
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	iface := r.URL.Query().Get("interface")
	since := querySince(r, "since", time.Hour)
	samples, err := db.QueryInterfaceSamples(ctx, iface, since, time.Now(), queryInt(r, "limit", 2000, 1, 20000))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	snap := s.backend.State().Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"samples": samples,
		"current": map[string]float64{"rx_bps": snap.RxBps, "tx_bps": snap.TxBps},
	})
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	matches, err := db.QueryThreatMatches(ctx, querySince(r, "since", 30*24*time.Hour),
		queryInt(r, "limit", 200, 1, 2000))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	total, bySource, _ := db.IndicatorCount(ctx)
	feeds, _ := db.FeedStatuses(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"matches":              matches,
		"indicators":           total,
		"indicators_by_source": bySource,
		"feeds":                feeds,
	})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	paths, err := db.RecentRoutePaths(ctx, queryInt(r, "limit", 50, 1, 500))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	live, liveErr := s.backend.State().Snapshot(), error(nil)
	resp := map[string]any{"paths": paths, "gateway": live.Gateway, "interface": live.Interface}
	if liveErr != nil {
		resp["error"] = liveErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTasks reports scheduler statistics, which is how an operator confirms that
// monitoring is actually running.
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.backend.Scheduler().Stats()})
}

// handlePrivileges publishes the privilege matrix, so the dashboard can explain any
// missing capability instead of silently showing empty charts.
func (s *Server) handlePrivileges(w http.ResponseWriter, r *http.Request) {
	caps := s.backend.Capabilities()
	report := security.BuildPrivilegeReport(security.Capabilities{
		Platform:           caps.Platform,
		Elevated:           caps.Elevated,
		Interfaces:         caps.Interfaces,
		Routes:             caps.Routes,
		Connections:        caps.Connections,
		ProcessAttribution: caps.ProcessAttribution,
		Wireless:           caps.Wireless,
		ICMP:               caps.ICMP,
		Traceroute:         caps.Traceroute,
		DNSServers:         caps.DNSServers,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"privileges":   report,
		"capabilities": caps,
	})
}

// handleSummary is the dashboard's single bootstrap request: everything the Overview
// needs in one round trip.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.backend.DB()
	cfg := s.backend.Config()
	now := time.Now()

	snap := s.backend.State().Snapshot()
	latest, _, _ := db.LatestSpeedTest(ctx, database.SpeedModeFull)
	av, _ := db.AvailabilitySince(ctx, now.Add(-24*time.Hour))
	day, _ := db.SpeedStats(ctx, "day", now.Add(-24*time.Hour), now,
		cfg.SpeedTest.ExpectedDownloadMbps, cfg.SpeedTest.ExpectedUploadMbps)
	sev, _ := db.SeverityCounts(ctx, now.Add(-24*time.Hour))
	recent, _ := db.QueryEvents(ctx, database.EventFilter{
		Since: now.Add(-24 * time.Hour), Limit: 25,
	})
	counts, _ := db.Counts(ctx)

	bySeverity := map[string]int64{}
	for k, v := range sev {
		bySeverity[k.String()] = v
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             snap,
		"last_speed_test":    latest,
		"availability_24h":   av,
		"speed_day":          day,
		"events_by_severity": bySeverity,
		"recent_events":      recent,
		"row_counts":         counts,
		"tasks":              s.backend.Scheduler().Stats(),
		"generated_at":       now,
	})
}

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	rows, err := s.backend.DB().LoadBaselines(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric != "" {
		filtered := rows[:0]
		for _, b := range rows {
			if b.Metric == metric {
				filtered = append(filtered, b)
			}
		}
		rows = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"baselines": rows, "count": len(rows)})
}

// testHandler runs a scheduler task on demand. Manual tests generate real network
// traffic, so they are rate limited, restricted to local clients unless explicitly
// allowed, and recorded as an event with their source.
func (s *Server) testHandler(task, label string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLocalRequest(r) && !s.cfg.Dashboard.AllowRemoteTests {
			writeError(w, http.StatusForbidden, "remote_tests_disabled",
				"tests may only be started from this host; set dashboard.allow_remote_tests to change that")
			return
		}
		if ok, retry := s.limiter.allow(clientKey(r) + "|" + task); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("too many test requests; retry in %s", retry.Round(time.Second)))
			return
		}

		s.log.Emit(events.New(events.ManualTestRequested).
			WithField("Test", label).
			WithField("Source", "api").
			WithField("Client", clientKey(r)))

		start := time.Now()
		err := s.backend.Scheduler().Trigger(r.Context(), task)
		resp := map[string]any{
			"test":     label,
			"task":     task,
			"duration": time.Since(start).String(),
			"ok":       err == nil,
		}
		if err != nil {
			resp["error"] = err.Error()
			// A task that is not registered means the collector is disabled in
			// configuration; that is a client error, not a server fault.
			if strings.Contains(err.Error(), "no such task") {
				writeJSON(w, http.StatusNotFound, resp)
				return
			}
			writeJSON(w, http.StatusInternalServerError, resp)
			return
		}
		resp["status"] = s.backend.State().Snapshot()
		writeJSON(w, http.StatusOK, resp)
	}
}
