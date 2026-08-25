package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/util"
)

// InsertSpeedTest stores a speed-test result.
func (d *DB) InsertSpeedTest(ctx context.Context, t SpeedTest) (int64, error) {
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO speed_tests (ts, mode, provider, endpoint, endpoint_location,
			download_mbps, upload_mbps, download_p90_mbps, upload_p90_mbps,
			latency_ms, jitter_ms, packet_loss_pct, tcp_connect_ms, dns_ms, ttfb_ms,
			bytes_down, bytes_up, streams, duration_ms, status, error,
			expected_download_mbps, expected_upload_mbps, iface, public_ip, isp, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(t.Time), t.Mode, NullString(t.Provider), NullString(t.Endpoint), NullString(t.EndpointLocation),
		t.DownloadMbps, t.UploadMbps, t.DownloadP90Mbps, t.UploadP90Mbps,
		t.LatencyMS, t.JitterMS, t.PacketLossPct, t.TCPConnectMS, t.DNSMS, t.TTFBMS,
		t.BytesDown, t.BytesUp, t.Streams, t.Duration.Milliseconds(), t.Status, NullString(t.Error),
		t.ExpectedDownload, t.ExpectedUpload, NullString(t.Interface), NullString(t.PublicIP),
		NullString(t.ISP), NullString(t.Raw))
	if err != nil {
		return 0, fmt.Errorf("insert speed test: %w", err)
	}
	return res.LastInsertId()
}

const speedSelect = `SELECT id, ts, mode, provider, endpoint, endpoint_location,
	download_mbps, upload_mbps, download_p90_mbps, upload_p90_mbps,
	latency_ms, jitter_ms, packet_loss_pct, tcp_connect_ms, dns_ms, ttfb_ms,
	bytes_down, bytes_up, streams, duration_ms, status, error,
	expected_download_mbps, expected_upload_mbps, iface, public_ip, isp
	FROM speed_tests`

func scanSpeedTest(sc interface{ Scan(...any) error }) (SpeedTest, error) {
	var (
		t                                              SpeedTest
		ts, durMS                                      int64
		prov, ep, loc, status, errStr, iface, pip, isp sql.NullString
		dl, ul, dl90, ul90, lat, jit, loss             sql.NullFloat64
		tcpc, dns, ttfb, expDL, expUL                  sql.NullFloat64
		bd, bu                                         sql.NullInt64
		streams                                        sql.NullInt64
	)
	if err := sc.Scan(&t.ID, &ts, &t.Mode, &prov, &ep, &loc,
		&dl, &ul, &dl90, &ul90, &lat, &jit, &loss, &tcpc, &dns, &ttfb,
		&bd, &bu, &streams, &durMS, &status, &errStr, &expDL, &expUL, &iface, &pip, &isp); err != nil {
		return SpeedTest{}, err
	}
	t.Time = FromMicros(ts)
	t.Provider, t.Endpoint, t.EndpointLocation = str(prov), str(ep), str(loc)
	t.DownloadMbps, t.UploadMbps = f64(dl), f64(ul)
	t.DownloadP90Mbps, t.UploadP90Mbps = f64(dl90), f64(ul90)
	t.LatencyMS, t.JitterMS, t.PacketLossPct = f64(lat), f64(jit), f64(loss)
	t.TCPConnectMS, t.DNSMS, t.TTFBMS = f64(tcpc), f64(dns), f64(ttfb)
	t.BytesDown, t.BytesUp = i64(bd), i64(bu)
	t.Streams = int(i64(streams))
	t.Duration = time.Duration(durMS) * time.Millisecond
	t.Status, t.Error = str(status), str(errStr)
	t.ExpectedDownload, t.ExpectedUpload = f64(expDL), f64(expUL)
	t.Interface, t.PublicIP, t.ISP = str(iface), str(pip), str(isp)
	return t, nil
}

// LatestSpeedTest returns the newest result, optionally restricted to a mode.
func (d *DB) LatestSpeedTest(ctx context.Context, mode string) (SpeedTest, bool, error) {
	q := speedSelect + ` WHERE status = 'ok'`
	var args []any
	if mode != "" {
		q += " AND mode = ?"
		args = append(args, mode)
	}
	q += " ORDER BY ts DESC LIMIT 1"
	t, err := scanSpeedTest(d.r.QueryRowContext(ctx, q, args...))
	if err == sql.ErrNoRows {
		return SpeedTest{}, false, nil
	}
	if err != nil {
		return SpeedTest{}, false, err
	}
	return t, true, nil
}

// QuerySpeedTests returns results in a window, newest first.
func (d *DB) QuerySpeedTests(ctx context.Context, mode string, since, until time.Time, limit int) ([]SpeedTest, error) {
	q := speedSelect + " WHERE 1=1"
	var args []any
	if mode != "" {
		q += " AND mode = ?"
		args = append(args, mode)
	}
	if !since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ToMicros(since))
	}
	if !until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, ToMicros(until))
	}
	if limit <= 0 {
		limit = 200
	}
	q += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limit)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query speed tests: %w", err)
	}
	defer rows.Close()
	var out []SpeedTest
	for rows.Next() {
		t, err := scanSpeedTest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SpeedSummary is the historical performance analysis for one window.
type SpeedSummary struct {
	Window   string     `json:"window"`
	Since    time.Time  `json:"since"`
	Until    time.Time  `json:"until"`
	Samples  int        `json:"samples"`
	Download util.Stats `json:"download"`
	Upload   util.Stats `json:"upload"`
	Latency  util.Stats `json:"latency"`
	Jitter   util.Stats `json:"jitter"`
	Loss     util.Stats `json:"packet_loss"`
	// PercentBelowBaseline is the share of samples below the median of the window,
	// which describes how consistent the link is.
	DownloadPercentBelowBaseline float64 `json:"download_percent_below_baseline"`
	UploadPercentBelowBaseline   float64 `json:"upload_percent_below_baseline"`
	// PercentBelowExpected is the share of samples below the configured ISP plan.
	DownloadPercentBelowExpected float64 `json:"download_percent_below_expected"`
	UploadPercentBelowExpected   float64 `json:"upload_percent_below_expected"`
	ExpectedDownload             float64 `json:"expected_download_mbps,omitempty"`
	ExpectedUpload               float64 `json:"expected_upload_mbps,omitempty"`
}

// SpeedStats computes the historical analysis for a window. Only successful full and
// manual tests are included: lightweight probes measure a different thing and would
// bias the numbers downward.
func (d *DB) SpeedStats(ctx context.Context, window string, since, until time.Time, expectedDL, expectedUL float64) (SpeedSummary, error) {
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT download_mbps, upload_mbps, latency_ms, jitter_ms, packet_loss_pct
		 FROM speed_tests
		 WHERE status = 'ok' AND mode IN ('full','manual') AND ts >= ? AND ts <= ?`,
		ToMicros(since), ToMicros(until))
	if err != nil {
		return SpeedSummary{}, fmt.Errorf("speed stats: %w", err)
	}
	defer rows.Close()

	var dl, ul, lat, jit, loss []float64
	for rows.Next() {
		var a, b, c, e, f sql.NullFloat64
		if err := rows.Scan(&a, &b, &c, &e, &f); err != nil {
			return SpeedSummary{}, err
		}
		if a.Valid && a.Float64 > 0 {
			dl = append(dl, a.Float64)
		}
		if b.Valid && b.Float64 > 0 {
			ul = append(ul, b.Float64)
		}
		if c.Valid && c.Float64 > 0 {
			lat = append(lat, c.Float64)
		}
		if e.Valid {
			jit = append(jit, e.Float64)
		}
		if f.Valid {
			loss = append(loss, f.Float64)
		}
	}
	if err := rows.Err(); err != nil {
		return SpeedSummary{}, err
	}

	s := SpeedSummary{
		Window: window, Since: since, Until: until, Samples: len(dl),
		Download: util.Describe(dl), Upload: util.Describe(ul),
		Latency: util.Describe(lat), Jitter: util.Describe(jit), Loss: util.Describe(loss),
		ExpectedDownload: expectedDL, ExpectedUpload: expectedUL,
	}
	s.DownloadPercentBelowBaseline = util.PercentBelow(dl, s.Download.Median)
	s.UploadPercentBelowBaseline = util.PercentBelow(ul, s.Upload.Median)
	if expectedDL > 0 {
		s.DownloadPercentBelowExpected = util.PercentBelow(dl, expectedDL)
	}
	if expectedUL > 0 {
		s.UploadPercentBelowExpected = util.PercentBelow(ul, expectedUL)
	}
	return s, nil
}
