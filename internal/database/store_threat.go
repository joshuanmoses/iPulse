package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// UpsertIndicators imports a batch of indicators from one feed. Existing indicators
// have their last_in_feed refreshed, which is what lets ExpireIndicators drop entries
// a feed has stopped publishing.
func (d *DB) UpsertIndicators(ctx context.Context, source string, inds []Indicator) (added, updated int64, err error) {
	if len(inds) == 0 {
		return 0, 0, nil
	}
	now := ToMicros(time.Now())
	err = d.InTx(ctx, func(tx *sql.Tx) error {
		// Two statements rather than an upsert: SQLite reports one changed row for
		// both branches of ON CONFLICT DO UPDATE, so an upsert cannot tell the caller
		// how many indicators are genuinely new.
		ins, err := tx.PrepareContext(ctx,
			`INSERT OR IGNORE INTO threat_indicators
			   (indicator, kind, source, confidence, note, ip_lo, ip_hi, first_imported, last_in_feed)
			 VALUES (?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		upd, err := tx.PrepareContext(ctx,
			`UPDATE threat_indicators
			 SET confidence = ?, note = COALESCE(?, note), last_in_feed = ?
			 WHERE indicator = ? AND kind = ? AND source = ?`)
		if err != nil {
			return err
		}
		defer upd.Close()

		for _, ind := range inds {
			lo, hi := indicatorRange(ind)
			conf := defaultConfidence(ind.Confidence)
			res, err := ins.ExecContext(ctx, ind.Indicator, ind.Kind, source,
				conf, NullString(ind.Note), lo, hi, now, now)
			if err != nil {
				return fmt.Errorf("import indicator %q: %w", ind.Indicator, err)
			}
			if n, _ := res.RowsAffected(); n == 1 {
				added++
				continue
			}
			if _, err := upd.ExecContext(ctx, conf, NullString(ind.Note), now,
				ind.Indicator, ind.Kind, source); err != nil {
				return fmt.Errorf("refresh indicator %q: %w", ind.Indicator, err)
			}
			updated++
		}
		return nil
	})
	return added, updated, err
}

// indicatorRange converts an IP or CIDR indicator into an inclusive byte range so
// containment can be tested with an indexed comparison instead of a table scan.
// Addresses are normalised to 16 bytes so IPv4 and IPv6 share one comparable ordering.
func indicatorRange(ind Indicator) (lo, hi any) {
	switch strings.ToLower(ind.Kind) {
	case IndicatorIP:
		if addr, err := netip.ParseAddr(ind.Indicator); err == nil {
			b := addr16(addr)
			return b, b
		}
	case IndicatorCIDR:
		if p, err := netip.ParsePrefix(ind.Indicator); err == nil {
			return prefixRange(p)
		}
	}
	return nil, nil
}

func addr16(a netip.Addr) []byte {
	b := a.Unmap().As16()
	return b[:]
}

func prefixRange(p netip.Prefix) ([]byte, []byte) {
	p = p.Masked()
	lo := p.Addr()
	bits := p.Bits()
	if lo.Is4() {
		bits += 96 // IPv4-mapped range inside the 128-bit space
	}
	loB := addr16(lo)
	hiB := make([]byte, 16)
	copy(hiB, loB)
	for i := bits; i < 128; i++ {
		hiB[i/8] |= 1 << (7 - uint(i%8))
	}
	return loB, hiB
}

func defaultConfidence(c string) string {
	switch strings.ToLower(c) {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return strings.ToLower(c)
	}
	return ConfidenceMedium
}

// MatchIP returns indicators matching an address, either exactly or by containing CIDR.
func (d *DB) MatchIP(ctx context.Context, ip netip.Addr) ([]Indicator, error) {
	key := addr16(ip)
	rows, err := d.r.QueryContext(ctx,
		`SELECT id, indicator, kind, source, confidence, note, first_imported, last_in_feed
		 FROM threat_indicators
		 WHERE ip_lo IS NOT NULL AND ip_lo <= ? AND ip_hi >= ?
		 ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END
		 LIMIT 25`, key, key)
	if err != nil {
		return nil, fmt.Errorf("match ip: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

// MatchDomain returns indicators matching a domain, including parent-domain matches so
// a blocklist entry for example.com also matches host.example.com.
func (d *DB) MatchDomain(ctx context.Context, domain string) ([]Indicator, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, nil
	}
	candidates := []string{domain}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}
	place := make([]string, len(candidates))
	args := make([]any, 0, len(candidates)+1)
	args = append(args, IndicatorDomain)
	for i, c := range candidates {
		place[i] = "?"
		args = append(args, c)
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT id, indicator, kind, source, confidence, note, first_imported, last_in_feed
		 FROM threat_indicators WHERE kind = ? AND indicator IN (`+strings.Join(place, ",")+`) LIMIT 25`, args...)
	if err != nil {
		return nil, fmt.Errorf("match domain: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

func scanIndicators(rows *sql.Rows) ([]Indicator, error) {
	var out []Indicator
	for rows.Next() {
		var (
			ind         Indicator
			note        sql.NullString
			first, last int64
		)
		if err := rows.Scan(&ind.ID, &ind.Indicator, &ind.Kind, &ind.Source, &ind.Confidence, &note, &first, &last); err != nil {
			return nil, err
		}
		ind.Note = str(note)
		ind.FirstImported, ind.LastInFeed = FromMicros(first), FromMicros(last)
		out = append(out, ind)
	}
	return out, rows.Err()
}

// IndicatorCount returns how many indicators are stored, in total and per source.
func (d *DB) IndicatorCount(ctx context.Context) (int64, map[string]int64, error) {
	var total int64
	if err := d.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_indicators`).Scan(&total); err != nil {
		return 0, nil, err
	}
	rows, err := d.r.QueryContext(ctx, `SELECT source, COUNT(*) FROM threat_indicators GROUP BY source`)
	if err != nil {
		return total, nil, err
	}
	defer rows.Close()
	bySource := map[string]int64{}
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			return total, bySource, err
		}
		bySource[s] = n
	}
	return total, bySource, rows.Err()
}

// ExpireIndicators removes indicators a feed has stopped publishing.
func (d *DB) ExpireIndicators(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := d.w.ExecContext(ctx, `DELETE FROM threat_indicators WHERE last_in_feed < ?`, ToMicros(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteIndicatorsBySource removes every indicator from one feed.
func (d *DB) DeleteIndicatorsBySource(ctx context.Context, source string) (int64, error) {
	res, err := d.w.ExecContext(ctx, `DELETE FROM threat_indicators WHERE source = ?`, source)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertThreatMatch records a match against local threat intelligence.
func (d *DB) InsertThreatMatch(ctx context.Context, m ThreatMatch) (int64, error) {
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO threat_matches (ts, indicator, indicator_kind, source, confidence,
			remote_ip, remote_port, protocol, domain, pid, process, exe, username,
			bytes_sent, bytes_recv, event_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(m.Time), m.Indicator, m.Kind, m.Source, m.Confidence,
		NullString(m.RemoteIP), m.RemotePort, NullString(m.Protocol), NullString(m.Domain),
		m.PID, NullString(m.Process), NullString(m.Exe), NullString(m.User),
		m.BytesSent, m.BytesRecv, m.EventID)
	if err != nil {
		return 0, fmt.Errorf("insert threat match: %w", err)
	}
	return res.LastInsertId()
}

// QueryThreatMatches returns recent matches.
func (d *DB) QueryThreatMatches(ctx context.Context, since time.Time, limit int) ([]ThreatMatch, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT id, ts, indicator, indicator_kind, source, confidence, remote_ip, remote_port,
	             protocol, domain, pid, process, exe, username, bytes_sent, bytes_recv, event_id
	      FROM threat_matches WHERE 1=1`
	var args []any
	if !since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ToMicros(since))
	}
	q += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limit)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query threat matches: %w", err)
	}
	defer rows.Close()
	var out []ThreatMatch
	for rows.Next() {
		var (
			m                              ThreatMatch
			ts                             int64
			ip, proto, dom, proc, exe, usr sql.NullString
			port, pid, sent, recv, evID    sql.NullInt64
		)
		if err := rows.Scan(&m.ID, &ts, &m.Indicator, &m.Kind, &m.Source, &m.Confidence,
			&ip, &port, &proto, &dom, &pid, &proc, &exe, &usr, &sent, &recv, &evID); err != nil {
			return nil, err
		}
		m.Time = FromMicros(ts)
		m.RemoteIP, m.Protocol, m.Domain = str(ip), str(proto), str(dom)
		m.Process, m.Exe, m.User = str(proc), str(exe), str(usr)
		m.RemotePort, m.PID = int(i64(port)), int(i64(pid))
		m.BytesSent, m.BytesRecv, m.EventID = i64(sent), i64(recv), i64(evID)
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetFeedStatus records the outcome of a feed import.
func (d *DB) SetFeedStatus(ctx context.Context, s FeedStatus) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO threat_feeds (name, last_import, last_success, indicators, last_error, etag)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET
		   last_import  = excluded.last_import,
		   last_success = COALESCE(excluded.last_success, threat_feeds.last_success),
		   indicators   = excluded.indicators,
		   last_error   = excluded.last_error,
		   etag         = COALESCE(excluded.etag, threat_feeds.etag)`,
		s.Name, NullTime(s.LastImport), NullTime(s.LastSuccess), s.Indicators,
		NullString(s.LastError), NullString(s.ETag))
	return err
}

// FeedStatuses returns the import state of every known feed.
func (d *DB) FeedStatuses(ctx context.Context) ([]FeedStatus, error) {
	rows, err := d.r.QueryContext(ctx,
		`SELECT name, last_import, last_success, indicators, last_error, etag FROM threat_feeds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedStatus
	for rows.Next() {
		var (
			s          FeedStatus
			imp, succ  sql.NullInt64
			errStr, et sql.NullString
		)
		if err := rows.Scan(&s.Name, &imp, &succ, &s.Indicators, &errStr, &et); err != nil {
			return nil, err
		}
		s.LastImport, s.LastSuccess = scanTime(imp), scanTime(succ)
		s.LastError, s.ETag = str(errStr), str(et)
		out = append(out, s)
	}
	return out, rows.Err()
}
