package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SaveBaseline persists one baseline bucket.
func (d *DB) SaveBaseline(ctx context.Context, b BaselineRow) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO baselines (metric, dimension, bucket, samples, mean, m2, min, max, ewma,
			median, mad, p10, p25, p75, p90, p95, p99, reservoir, established, first_seen, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(metric, dimension, bucket) DO UPDATE SET
		   samples=excluded.samples, mean=excluded.mean, m2=excluded.m2,
		   min=excluded.min, max=excluded.max, ewma=excluded.ewma,
		   median=excluded.median, mad=excluded.mad, p10=excluded.p10, p25=excluded.p25,
		   p75=excluded.p75, p90=excluded.p90, p95=excluded.p95, p99=excluded.p99,
		   reservoir=excluded.reservoir, established=excluded.established,
		   updated_at=excluded.updated_at`,
		b.Metric, b.Dimension, b.Bucket, b.Samples, b.Mean, b.M2, b.Min, b.Max, b.EWMA,
		b.Median, b.MAD, b.P10, b.P25, b.P75, b.P90, b.P95, b.P99, NullString(b.Reservoir),
		boolInt(b.Established), ToMicros(b.FirstSeen), ToMicros(b.UpdatedAt))
	if err != nil {
		return fmt.Errorf("save baseline %s/%s/%s: %w", b.Metric, b.Dimension, b.Bucket, err)
	}
	return nil
}

// SaveBaselines persists a batch in one transaction.
func (d *DB) SaveBaselines(ctx context.Context, rows []BaselineRow) error {
	if len(rows) == 0 {
		return nil
	}
	return d.InTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO baselines (metric, dimension, bucket, samples, mean, m2, min, max, ewma,
				median, mad, p10, p25, p75, p90, p95, p99, reservoir, established, first_seen, updated_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			 ON CONFLICT(metric, dimension, bucket) DO UPDATE SET
			   samples=excluded.samples, mean=excluded.mean, m2=excluded.m2,
			   min=excluded.min, max=excluded.max, ewma=excluded.ewma,
			   median=excluded.median, mad=excluded.mad, p10=excluded.p10, p25=excluded.p25,
			   p75=excluded.p75, p90=excluded.p90, p95=excluded.p95, p99=excluded.p99,
			   reservoir=excluded.reservoir, established=excluded.established,
			   updated_at=excluded.updated_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, b := range rows {
			if _, err := stmt.ExecContext(ctx, b.Metric, b.Dimension, b.Bucket, b.Samples, b.Mean, b.M2,
				b.Min, b.Max, b.EWMA, b.Median, b.MAD, b.P10, b.P25, b.P75, b.P90, b.P95, b.P99,
				NullString(b.Reservoir), boolInt(b.Established), ToMicros(b.FirstSeen), ToMicros(b.UpdatedAt)); err != nil {
				return fmt.Errorf("save baseline %s: %w", b.Metric, err)
			}
		}
		return nil
	})
}

// LoadBaselines reads every stored baseline, so the engine survives a restart with its
// learned history intact.
func (d *DB) LoadBaselines(ctx context.Context) ([]BaselineRow, error) {
	rows, err := d.r.QueryContext(ctx,
		`SELECT metric, dimension, bucket, samples, mean, m2, min, max, ewma, median, mad,
		        p10, p25, p75, p90, p95, p99, reservoir, established, first_seen, updated_at
		 FROM baselines`)
	if err != nil {
		return nil, fmt.Errorf("load baselines: %w", err)
	}
	defer rows.Close()
	var out []BaselineRow
	for rows.Next() {
		var (
			b                            BaselineRow
			mn, mx, ewma, med, mad       sql.NullFloat64
			p10, p25, p75, p90, p95, p99 sql.NullFloat64
			reservoir                    sql.NullString
			established                  int
			firstSeen, updatedAt         sql.NullInt64
		)
		if err := rows.Scan(&b.Metric, &b.Dimension, &b.Bucket, &b.Samples, &b.Mean, &b.M2,
			&mn, &mx, &ewma, &med, &mad, &p10, &p25, &p75, &p90, &p95, &p99,
			&reservoir, &established, &firstSeen, &updatedAt); err != nil {
			return nil, err
		}
		b.Min, b.Max, b.EWMA, b.Median, b.MAD = f64(mn), f64(mx), f64(ewma), f64(med), f64(mad)
		b.P10, b.P25, b.P75, b.P90, b.P95, b.P99 = f64(p10), f64(p25), f64(p75), f64(p90), f64(p95), f64(p99)
		b.Reservoir = str(reservoir)
		b.Established = established != 0
		b.FirstSeen, b.UpdatedAt = scanTime(firstSeen), scanTime(updatedAt)
		out = append(out, b)
	}
	return out, rows.Err()
}

// PruneBaselines removes buckets that have not been updated recently, so a machine
// that changes networks does not carry stale baselines forever.
func (d *DB) PruneBaselines(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := d.w.ExecContext(ctx, `DELETE FROM baselines WHERE updated_at < ?`, ToMicros(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
