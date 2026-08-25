package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// OpenOutage records the start of an outage and returns its id. If an outage is
// already open it is returned instead, with its diagnostics counter incremented: a
// single event of connectivity loss must never produce a stream of outage rows.
func (d *DB) OpenOutage(ctx context.Context, o Outage) (int64, error) {
	if cur, ok, err := d.CurrentOutage(ctx); err != nil {
		return 0, err
	} else if ok {
		_, err := d.w.ExecContext(ctx,
			`UPDATE outages SET diagnostics_count = diagnostics_count + 1,
			     classification = ?, probable_cause = ?, evidence = ?
			 WHERE id = ?`,
			o.Classification, NullString(o.ProbableCause), NullString(o.Evidence), cur.ID)
		return cur.ID, err
	}
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO outages (started_at, classification, probable_cause, evidence, iface, gateway, public_ip, resolved)
		 VALUES (?,?,?,?,?,?,?,0)`,
		ToMicros(o.Start), o.Classification, NullString(o.ProbableCause), NullString(o.Evidence),
		NullString(o.Interface), NullString(o.Gateway), NullString(o.PublicIP))
	if err != nil {
		return 0, fmt.Errorf("open outage: %w", err)
	}
	return res.LastInsertId()
}

// CloseOutage marks an outage resolved and stores its duration.
func (d *DB) CloseOutage(ctx context.Context, id int64, end time.Time) (Outage, error) {
	o, ok, err := d.outageByID(ctx, id)
	if err != nil || !ok {
		return Outage{}, err
	}
	// Stored durations have millisecond resolution, so round here too: a caller
	// comparing the returned value with the stored one must see the same number.
	dur := end.Sub(o.Start).Round(time.Millisecond)
	if dur < 0 {
		dur = 0
	}
	if _, err := d.w.ExecContext(ctx,
		`UPDATE outages SET ended_at = ?, duration_ms = ?, resolved = 1 WHERE id = ?`,
		ToMicros(end), dur.Milliseconds(), id); err != nil {
		return Outage{}, fmt.Errorf("close outage: %w", err)
	}
	o.End, o.Duration, o.Resolved = end, dur, true
	return o, nil
}

const outageSelect = `SELECT id, started_at, ended_at, duration_ms, classification,
	probable_cause, evidence, iface, gateway, public_ip, resolved, diagnostics_count FROM outages`

func scanOutage(sc interface{ Scan(...any) error }) (Outage, error) {
	var (
		o                         Outage
		started                   int64
		ended, durMS              sql.NullInt64
		cause, ev, iface, gw, pip sql.NullString
		resolved, diag            int
	)
	if err := sc.Scan(&o.ID, &started, &ended, &durMS, &o.Classification,
		&cause, &ev, &iface, &gw, &pip, &resolved, &diag); err != nil {
		return Outage{}, err
	}
	o.Start = FromMicros(started)
	o.End = scanTime(ended)
	o.Duration = time.Duration(i64(durMS)) * time.Millisecond
	if o.Duration == 0 && !o.End.IsZero() {
		o.Duration = o.End.Sub(o.Start)
	}
	o.ProbableCause, o.Evidence = str(cause), str(ev)
	o.Interface, o.Gateway, o.PublicIP = str(iface), str(gw), str(pip)
	o.Resolved, o.Diagnostics = resolved != 0, diag
	return o, nil
}

func (d *DB) outageByID(ctx context.Context, id int64) (Outage, bool, error) {
	o, err := scanOutage(d.r.QueryRowContext(ctx, outageSelect+" WHERE id = ?", id))
	if err == sql.ErrNoRows {
		return Outage{}, false, nil
	}
	if err != nil {
		return Outage{}, false, err
	}
	return o, true, nil
}

// CurrentOutage returns the open outage, if any.
func (d *DB) CurrentOutage(ctx context.Context) (Outage, bool, error) {
	o, err := scanOutage(d.r.QueryRowContext(ctx,
		outageSelect+" WHERE resolved = 0 ORDER BY started_at DESC LIMIT 1"))
	if err == sql.ErrNoRows {
		return Outage{}, false, nil
	}
	if err != nil {
		return Outage{}, false, err
	}
	return o, true, nil
}

// QueryOutages returns outages in a window, newest first.
func (d *DB) QueryOutages(ctx context.Context, since, until time.Time, limit int) ([]Outage, error) {
	q := outageSelect + " WHERE 1=1"
	var args []any
	if !since.IsZero() {
		q += " AND started_at >= ?"
		args = append(args, ToMicros(since))
	}
	if !until.IsZero() {
		q += " AND started_at <= ?"
		args = append(args, ToMicros(until))
	}
	if limit <= 0 {
		limit = 100
	}
	q += " ORDER BY started_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query outages: %w", err)
	}
	defer rows.Close()
	var out []Outage
	for rows.Next() {
		o, err := scanOutage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Availability is the uptime summary for a window.
type Availability struct {
	Since         time.Time      `json:"since"`
	Until         time.Time      `json:"until"`
	Window        time.Duration  `json:"window"`
	Downtime      time.Duration  `json:"downtime"`
	Percent       float64        `json:"availability_percent"`
	Outages       int            `json:"outages"`
	LongestOutage time.Duration  `json:"longest_outage"`
	MTBF          time.Duration  `json:"mtbf,omitempty"`
	ByCause       map[string]int `json:"by_cause,omitempty"`
}

// AvailabilitySince computes availability over a window. Downtime is clipped to the
// window, so an outage that began before the window only contributes its overlap.
func (d *DB) AvailabilitySince(ctx context.Context, since time.Time) (Availability, error) {
	until := time.Now()
	a := Availability{Since: since, Until: until, Window: until.Sub(since), Percent: 100, ByCause: map[string]int{}}

	rows, err := d.r.QueryContext(ctx,
		`SELECT started_at, ended_at, classification FROM outages
		 WHERE (ended_at IS NULL OR ended_at >= ?) AND started_at <= ?`,
		ToMicros(since), ToMicros(until))
	if err != nil {
		return a, fmt.Errorf("availability: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var startMicros int64
		var endMicros sql.NullInt64
		var class string
		if err := rows.Scan(&startMicros, &endMicros, &class); err != nil {
			return a, err
		}
		start := FromMicros(startMicros)
		end := until
		if endMicros.Valid {
			end = FromMicros(endMicros.Int64)
		}
		if start.Before(since) {
			start = since
		}
		if end.After(until) {
			end = until
		}
		if d := end.Sub(start); d > 0 {
			a.Downtime += d
			if d > a.LongestOutage {
				a.LongestOutage = d
			}
		}
		a.Outages++
		a.ByCause[class]++
	}
	if err := rows.Err(); err != nil {
		return a, err
	}
	if a.Window > 0 {
		up := a.Window - a.Downtime
		if up < 0 {
			up = 0
		}
		a.Percent = float64(up) / float64(a.Window) * 100
	}
	if a.Outages > 0 {
		a.MTBF = (a.Window - a.Downtime) / time.Duration(a.Outages)
	}
	return a, nil
}
