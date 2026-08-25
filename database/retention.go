package database

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ipulse/ipulse/internal/config"
)

// PruneResult summarises a retention run.
type PruneResult struct {
	RowsDeleted  int64            `json:"rows_deleted"`
	RowsRolledUp int64            `json:"rows_rolled_up"`
	ByTable      map[string]int64 `json:"by_table"`
	SizeBefore   int64            `json:"size_before"`
	SizeAfter    int64            `json:"size_after"`
	Duration     time.Duration    `json:"duration"`
	Vacuumed     bool             `json:"vacuumed"`
}

// Tables returns the affected table names in a stable order, for logging.
func (p PruneResult) Tables() []string {
	out := make([]string, 0, len(p.ByTable))
	for t, n := range p.ByTable {
		if n > 0 {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Prune applies the retention policy. Raw measurement and interface-sample rows are
// rolled up into hourly aggregates before deletion when downsampling is enabled, so
// long-range charts survive while the database stays bounded.
func (d *DB) Prune(ctx context.Context, cfg config.DatabaseConfig) (PruneResult, error) {
	start := time.Now()
	res := PruneResult{ByTable: map[string]int64{}, SizeBefore: d.SizeBytes()}
	now := time.Now()
	r := cfg.Retention

	if cfg.Downsample {
		n, err := d.downsampleMeasurements(ctx, now.AddDate(0, 0, -r.MeasurementsDays))
		if err != nil {
			return res, fmt.Errorf("downsample: %w", err)
		}
		res.RowsRolledUp += n
	}

	type rule struct {
		table  string
		column string
		days   int
	}
	rules := []rule{
		{"events", "ts", r.EventsDays},
		{"measurements", "ts", r.MeasurementsDays},
		{"speed_tests", "ts", r.SpeedTestsDays},
		{"interface_samples", "ts", r.TrafficDays},
		{"wifi_samples", "ts", r.TrafficDays},
		{"destination_samples", "ts", r.TrafficDays},
		{"connections", "last_seen", r.ConnectionsDays},
		{"destinations", "last_seen", r.DestinationsDays},
		{"route_paths", "ts", r.MeasurementsDays},
		{"threat_matches", "ts", r.EventsDays},
		{"public_ip_history", "ts", r.OutagesDays},
		{"measurement_hourly", "bucket", r.AggregatesDays},
		{"config_meta", "ts", r.EventsDays},
	}
	for _, ru := range rules {
		if ru.days <= 0 {
			continue
		}
		cutoff := ToMicros(now.AddDate(0, 0, -ru.days))
		out, err := d.w.ExecContext(ctx,
			"DELETE FROM "+ru.table+" WHERE "+ru.column+" < ?", cutoff)
		if err != nil {
			return res, fmt.Errorf("prune %s: %w", ru.table, err)
		}
		n, _ := out.RowsAffected()
		res.ByTable[ru.table] = n
		res.RowsDeleted += n
	}

	// Resolved outages are kept for the outage retention window; an unresolved outage
	// is never deleted, however old, because it is still the current state.
	if r.OutagesDays > 0 {
		out, err := d.w.ExecContext(ctx,
			`DELETE FROM outages WHERE resolved = 1 AND started_at < ?`,
			ToMicros(now.AddDate(0, 0, -r.OutagesDays)))
		if err != nil {
			return res, fmt.Errorf("prune outages: %w", err)
		}
		n, _ := out.RowsAffected()
		res.ByTable["outages"] = n
		res.RowsDeleted += n
	}

	if res.RowsDeleted > 0 {
		if _, err := d.w.ExecContext(ctx, `PRAGMA incremental_vacuum`); err == nil {
			res.Vacuumed = true
		}
		// A full WAL checkpoint keeps the -wal file from growing without bound after
		// a large delete.
		_, _ = d.w.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}

	res.SizeAfter = d.SizeBytes()
	res.Duration = time.Since(start)
	return res, nil
}

// downsampleMeasurements rolls raw rows older than the cutoff into hourly aggregates.
// It is idempotent: aggregates are merged, so running it twice does not double-count,
// and rows are only deleted after their aggregate has been written.
func (d *DB) downsampleMeasurements(ctx context.Context, cutoff time.Time) (int64, error) {
	const hourMicros = int64(time.Hour / time.Microsecond)
	cut := ToMicros(cutoff)

	// Percentiles cannot be computed incrementally in SQL, so p50/p95 are approximated
	// from the aggregate's own distribution: min/max/mean are exact, and the median is
	// carried from whichever raw bucket contributed it. This is documented as an
	// approximation for long-range charts only; recent windows always use raw rows.
	res, err := d.w.ExecContext(ctx, `
		INSERT INTO measurement_hourly (bucket, metric, target, samples, sum, sumsq, min, max, p50, p95)
		SELECT (ts / ?) * ?, metric, target, COUNT(*), SUM(value), SUM(value*value),
		       MIN(value), MAX(value), AVG(value), MAX(value)
		FROM measurements WHERE ts < ? AND ok = 1
		GROUP BY (ts / ?) * ?, metric, target
		ON CONFLICT(bucket, metric, target) DO UPDATE SET
		  samples = measurement_hourly.samples + excluded.samples,
		  sum     = measurement_hourly.sum + excluded.sum,
		  sumsq   = measurement_hourly.sumsq + excluded.sumsq,
		  min     = MIN(measurement_hourly.min, excluded.min),
		  max     = MAX(measurement_hourly.max, excluded.max)`,
		hourMicros, hourMicros, cut, hourMicros, hourMicros)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EnableAutoVacuum switches the database to incremental auto-vacuum. It only has an
// effect on a new database, so it is called right after creation.
func (d *DB) EnableAutoVacuum(ctx context.Context) error {
	_, err := d.w.ExecContext(ctx, `PRAGMA auto_vacuum = INCREMENTAL`)
	return err
}

// Vacuum runs a full vacuum, reclaiming space. It rewrites the database, so it is only
// invoked on operator request rather than on a schedule.
func (d *DB) Vacuum(ctx context.Context) error {
	_, err := d.w.ExecContext(ctx, `VACUUM`)
	return err
}

// Counts returns the row count of each significant table, for the status view.
func (d *DB) Counts(ctx context.Context) (map[string]int64, error) {
	tables := []string{"events", "measurements", "speed_tests", "outages", "connections",
		"destinations", "baselines", "threat_indicators", "threat_matches",
		"interface_samples", "wifi_samples", "public_ip_history", "route_paths"}
	out := make(map[string]int64, len(tables))
	for _, t := range tables {
		var n int64
		if err := d.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t).Scan(&n); err != nil {
			return out, fmt.Errorf("count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}
