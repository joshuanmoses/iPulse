package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/events"
)

// InsertEvent stores an event and returns its row id.
func (d *DB) InsertEvent(ctx context.Context, ev events.Event) (int64, error) {
	fields, err := json.Marshal(ev.Fields.Map())
	if err != nil {
		fields = []byte("{}")
	}
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO events (ts, code, name, severity, category, message, process, destination,
		                     correlation_id, suppressed, fields, rendered)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(ev.Time), ev.Code, ev.Name, int(ev.Severity), string(ev.Category),
		NullString(ev.Message), NullString(ev.Process), NullString(ev.Destination),
		NullString(ev.CorrelationID), boolInt(ev.Suppressed), string(fields), ev.Text())
	if err != nil {
		return 0, fmt.Errorf("insert event IPULSE-%d: %w", ev.Code, err)
	}
	return res.LastInsertId()
}

// EventFilter selects stored events. Zero values mean "no constraint".
type EventFilter struct {
	Since       time.Time
	Until       time.Time
	MinSeverity *events.Severity
	Severity    *events.Severity
	Codes       []int
	Names       []string
	Categories  []string
	Process     string
	Destination string
	// Search matches the rendered text, so it finds a value in any field.
	Search            string
	IncludeSuppressed bool
	Limit             int
	Offset            int
	// Ascending returns oldest first; the default is newest first.
	Ascending bool
}

// QueryEvents returns stored events matching the filter.
func (d *DB) QueryEvents(ctx context.Context, f EventFilter) ([]StoredEvent, error) {
	where, args := f.build()
	order := "DESC"
	if f.Ascending {
		order = "ASC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 10000 {
		limit = 10000
	}
	q := `SELECT id, ts, code, name, severity, category, message, process, destination,
	             correlation_id, suppressed, fields, rendered
	      FROM events ` + where + ` ORDER BY ts ` + order + `, id ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, limit, f.Offset)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var out []StoredEvent
	for rows.Next() {
		var (
			e                                        StoredEvent
			ts                                       int64
			sev, suppressed                          int
			msg, proc, dest, corr, fieldsJSON, rende sql.NullString
		)
		if err := rows.Scan(&e.ID, &ts, &e.Code, &e.Name, &sev, &e.Category,
			&msg, &proc, &dest, &corr, &suppressed, &fieldsJSON, &rende); err != nil {
			return nil, err
		}
		e.Time = FromMicros(ts)
		e.Severity = events.Severity(sev)
		e.Message, e.Process, e.Destination, e.CorrelationID = str(msg), str(proc), str(dest), str(corr)
		e.Suppressed = suppressed != 0
		e.Rendered = str(rende)
		if s := str(fieldsJSON); s != "" {
			_ = json.Unmarshal([]byte(s), &e.Fields)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEvents returns the number of events matching the filter.
func (d *DB) CountEvents(ctx context.Context, f EventFilter) (int64, error) {
	where, args := f.build()
	var n int64
	err := d.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events `+where, args...).Scan(&n)
	return n, err
}

// SeverityCounts returns the number of events per severity since a time.
func (d *DB) SeverityCounts(ctx context.Context, since time.Time) (map[events.Severity]int64, error) {
	rows, err := d.r.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM events WHERE ts >= ? AND suppressed = 0 GROUP BY severity`,
		ToMicros(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[events.Severity]int64{}
	for rows.Next() {
		var sev int
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[events.Severity(sev)] = n
	}
	return out, rows.Err()
}

// TopEventCodes returns the most frequent event codes since a time.
func (d *DB) TopEventCodes(ctx context.Context, since time.Time, limit int) ([]EventCount, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT code, name, severity, COUNT(*) AS n FROM events
		 WHERE ts >= ? AND suppressed = 0 GROUP BY code ORDER BY n DESC LIMIT ?`,
		ToMicros(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventCount
	for rows.Next() {
		var ec EventCount
		var sev int
		if err := rows.Scan(&ec.Code, &ec.Name, &sev, &ec.Count); err != nil {
			return nil, err
		}
		ec.Severity = events.Severity(sev)
		out = append(out, ec)
	}
	return out, rows.Err()
}

// EventCount is an aggregated event tally.
type EventCount struct {
	Code     int             `json:"code"`
	Name     string          `json:"name"`
	Severity events.Severity `json:"severity"`
	Count    int64           `json:"count"`
}

// MarkSuppressed flags events as absorbed by a correlation rule. They stay in the
// database for forensics but disappear from the readable log view.
func (d *DB) MarkSuppressed(ctx context.Context, ids []int64, correlationID string) error {
	if len(ids) == 0 {
		return nil
	}
	place := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, correlationID)
	for i, id := range ids {
		place[i] = "?"
		args = append(args, id)
	}
	_, err := d.w.ExecContext(ctx,
		`UPDATE events SET suppressed = 1, correlation_id = ? WHERE id IN (`+strings.Join(place, ",")+`)`,
		args...)
	return err
}

func (f EventFilter) build() (string, []any) {
	var conds []string
	var args []any
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, ToMicros(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "ts <= ?")
		args = append(args, ToMicros(f.Until))
	}
	if f.Severity != nil {
		conds = append(conds, "severity = ?")
		args = append(args, int(*f.Severity))
	} else if f.MinSeverity != nil {
		conds = append(conds, "severity >= ?")
		args = append(args, int(*f.MinSeverity))
	}
	if len(f.Codes) > 0 {
		place := make([]string, len(f.Codes))
		for i, c := range f.Codes {
			place[i] = "?"
			args = append(args, c)
		}
		conds = append(conds, "code IN ("+strings.Join(place, ",")+")")
	}
	if len(f.Names) > 0 {
		place := make([]string, len(f.Names))
		for i, n := range f.Names {
			place[i] = "?"
			args = append(args, strings.ToUpper(n))
		}
		conds = append(conds, "name IN ("+strings.Join(place, ",")+")")
	}
	if len(f.Categories) > 0 {
		place := make([]string, len(f.Categories))
		for i, c := range f.Categories {
			place[i] = "?"
			args = append(args, strings.ToUpper(c))
		}
		conds = append(conds, "category IN ("+strings.Join(place, ",")+")")
	}
	if f.Process != "" {
		conds = append(conds, `process LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.Process)+"%")
	}
	if f.Destination != "" {
		conds = append(conds, `destination LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.Destination)+"%")
	}
	if f.Search != "" {
		conds = append(conds, `rendered LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.Search)+"%")
	}
	if !f.IncludeSuppressed {
		conds = append(conds, "suppressed = 0")
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// escapeLike neutralises LIKE wildcards in user input so a search for "100%" does not
// turn into a match-everything pattern. Parameter binding already prevents injection;
// this is about predictable results.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
