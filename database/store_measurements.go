package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/util"
)

// InsertMeasurement stores one numeric observation.
func (d *DB) InsertMeasurement(ctx context.Context, m Measurement) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO measurements (ts, metric, value, unit, target, ok, meta) VALUES (?,?,?,?,?,?,?)`,
		ToMicros(m.Time), m.Metric, m.Value, NullString(m.Unit), m.Target, boolInt(m.OK), NullString(m.Meta))
	if err != nil {
		return fmt.Errorf("insert measurement %s: %w", m.Metric, err)
	}
	return nil
}

// InsertMeasurements stores a batch in one transaction. Collectors emit several
// related values per cycle, and a single transaction keeps the write cost flat.
func (d *DB) InsertMeasurements(ctx context.Context, ms []Measurement) error {
	if len(ms) == 0 {
		return nil
	}
	return d.InTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO measurements (ts, metric, value, unit, target, ok, meta) VALUES (?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, m := range ms {
			if _, err := stmt.ExecContext(ctx, ToMicros(m.Time), m.Metric, m.Value,
				NullString(m.Unit), m.Target, boolInt(m.OK), NullString(m.Meta)); err != nil {
				return fmt.Errorf("insert measurement %s: %w", m.Metric, err)
			}
		}
		return nil
	})
}

// MeasurementFilter selects stored measurements.
type MeasurementFilter struct {
	Metric string
	Target string
	Since  time.Time
	Until  time.Time
	OnlyOK bool
	Limit  int
	// Ascending returns oldest first, which is what charts want.
	Ascending bool
}

// QueryMeasurements returns matching measurements.
func (d *DB) QueryMeasurements(ctx context.Context, f MeasurementFilter) ([]Measurement, error) {
	q := `SELECT id, ts, metric, value, unit, target, ok, meta FROM measurements WHERE 1=1`
	var args []any
	if f.Metric != "" {
		q += " AND metric = ?"
		args = append(args, f.Metric)
	}
	if f.Target != "" {
		q += " AND target = ?"
		args = append(args, f.Target)
	}
	if !f.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ToMicros(f.Since))
	}
	if !f.Until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, ToMicros(f.Until))
	}
	if f.OnlyOK {
		q += " AND ok = 1"
	}
	if f.Ascending {
		q += " ORDER BY ts ASC"
	} else {
		q += " ORDER BY ts DESC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 5000
	}
	if limit > 500000 {
		limit = 500000
	}
	q += " LIMIT ?"
	args = append(args, limit)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query measurements: %w", err)
	}
	defer rows.Close()
	var out []Measurement
	for rows.Next() {
		var (
			m        Measurement
			ts       int64
			ok       int
			unit, mt sql.NullString
		)
		if err := rows.Scan(&m.ID, &ts, &m.Metric, &m.Value, &unit, &m.Target, &ok, &mt); err != nil {
			return nil, err
		}
		m.Time = FromMicros(ts)
		m.Unit, m.Meta, m.OK = str(unit), str(mt), ok != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// MetricValues returns just the values for a metric in a window, which is what the
// statistics and baseline code needs.
func (d *DB) MetricValues(ctx context.Context, metric, target string, since, until time.Time) ([]float64, error) {
	q := `SELECT value FROM measurements WHERE metric = ? AND ok = 1`
	args := []any{metric}
	if target != "" {
		q += " AND target = ?"
		args = append(args, target)
	}
	if !since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ToMicros(since))
	}
	if !until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, ToMicros(until))
	}
	// Bound the result so a very long window cannot allocate without limit.
	q += " ORDER BY ts DESC LIMIT 500000"

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("metric values %s: %w", metric, err)
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// MetricStats summarises a metric over a window.
func (d *DB) MetricStats(ctx context.Context, metric, target string, since, until time.Time) (util.Stats, error) {
	vals, err := d.MetricValues(ctx, metric, target, since, until)
	if err != nil {
		return util.Stats{}, err
	}
	return util.Describe(vals), nil
}

// LatestMeasurement returns the most recent value for a metric.
func (d *DB) LatestMeasurement(ctx context.Context, metric, target string) (Measurement, bool, error) {
	q := `SELECT id, ts, metric, value, unit, target, ok, meta FROM measurements WHERE metric = ?`
	args := []any{metric}
	if target != "" {
		q += " AND target = ?"
		args = append(args, target)
	}
	q += " ORDER BY ts DESC LIMIT 1"

	var (
		m        Measurement
		ts       int64
		ok       int
		unit, mt sql.NullString
	)
	err := d.r.QueryRowContext(ctx, q, args...).
		Scan(&m.ID, &ts, &m.Metric, &m.Value, &unit, &m.Target, &ok, &mt)
	if err == sql.ErrNoRows {
		return Measurement{}, false, nil
	}
	if err != nil {
		return Measurement{}, false, err
	}
	m.Time = FromMicros(ts)
	m.Unit, m.Meta, m.OK = str(unit), str(mt), ok != 0
	return m, true, nil
}

// TimeSeriesPoint is one point of a downsampled series for charting.
type TimeSeriesPoint struct {
	Time    time.Time `json:"t"`
	Value   float64   `json:"v"`
	Min     float64   `json:"min,omitempty"`
	Max     float64   `json:"max,omitempty"`
	Samples int       `json:"n,omitempty"`
}

// TimeSeries returns a metric bucketed to a fixed interval, so the dashboard can plot
// a month of data without transferring every raw row. Raw rows and hourly roll-ups are
// combined, which is what keeps long-range charts intact after retention pruning.
func (d *DB) TimeSeries(ctx context.Context, metric, target string, since, until time.Time, bucket time.Duration) ([]TimeSeriesPoint, error) {
	if bucket <= 0 {
		bucket = time.Minute
	}
	if until.IsZero() {
		until = time.Now()
	}
	bucketMicros := bucket.Microseconds()

	q := `SELECT (ts / ?) * ? AS b, AVG(value), MIN(value), MAX(value), COUNT(*)
	      FROM measurements WHERE metric = ? AND ok = 1 AND ts >= ? AND ts <= ?`
	args := []any{bucketMicros, bucketMicros, metric, ToMicros(since), ToMicros(until)}
	if target != "" {
		q += " AND target = ?"
		args = append(args, target)
	}
	q += " GROUP BY b ORDER BY b ASC LIMIT 20000"

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("time series %s: %w", metric, err)
	}
	defer rows.Close()
	var out []TimeSeriesPoint
	for rows.Next() {
		var b int64
		var p TimeSeriesPoint
		var n int
		if err := rows.Scan(&b, &p.Value, &p.Min, &p.Max, &n); err != nil {
			return nil, err
		}
		p.Time = FromMicros(b)
		p.Samples = n
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fill the older part of the range from hourly roll-ups when raw rows have been
	// pruned. Roll-ups are only used for buckets not already covered.
	if len(out) == 0 || out[0].Time.After(since.Add(bucket)) {
		agg, err := d.hourlySeries(ctx, metric, target, since, firstTime(out, until))
		if err == nil && len(agg) > 0 {
			out = append(agg, out...)
		}
	}
	return out, nil
}

func firstTime(pts []TimeSeriesPoint, fallback time.Time) time.Time {
	if len(pts) == 0 {
		return fallback
	}
	return pts[0].Time
}

func (d *DB) hourlySeries(ctx context.Context, metric, target string, since, until time.Time) ([]TimeSeriesPoint, error) {
	q := `SELECT bucket, sum, samples, min, max FROM measurement_hourly
	      WHERE metric = ? AND bucket >= ? AND bucket < ?`
	args := []any{metric, ToMicros(since), ToMicros(until)}
	if target != "" {
		q += " AND target = ?"
		args = append(args, target)
	}
	q += " ORDER BY bucket ASC LIMIT 20000"
	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimeSeriesPoint
	for rows.Next() {
		var bucket int64
		var sum, mn, mx float64
		var n int
		if err := rows.Scan(&bucket, &sum, &n, &mn, &mx); err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		out = append(out, TimeSeriesPoint{
			Time: FromMicros(bucket), Value: sum / float64(n), Min: mn, Max: mx, Samples: n,
		})
	}
	return out, rows.Err()
}
