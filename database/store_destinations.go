package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UpsertDestination accumulates one observation of a remote endpoint and returns the
// destination id along with whether this was the first time it was ever seen.
func (d *DB) UpsertDestination(ctx context.Context, dst Destination) (id int64, isNew bool, err error) {
	err = d.r.QueryRowContext(ctx,
		`SELECT id FROM destinations WHERE remote_ip = ? AND remote_port = ? AND protocol = ?`,
		dst.RemoteIP, dst.RemotePort, dst.Protocol).Scan(&id)
	switch {
	case err == sql.ErrNoRows:
		isNew = true
	case err != nil:
		return 0, false, fmt.Errorf("lookup destination: %w", err)
	}

	if isNew {
		res, ierr := d.w.ExecContext(ctx,
			`INSERT INTO destinations (remote_ip, remote_port, protocol, first_seen, last_seen,
				contacts, bytes_sent, bytes_recv, processes, rdns, asn, asn_org, country, internal)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			dst.RemoteIP, dst.RemotePort, dst.Protocol, ToMicros(dst.FirstSeen), ToMicros(dst.LastSeen),
			maxInt64(dst.Contacts, 1), dst.BytesSent, dst.BytesRecv, NullString(dst.Processes),
			NullString(dst.ReverseDNS), NullString(dst.ASN), NullString(dst.ASNOrg),
			NullString(dst.Country), boolInt(dst.Internal))
		if ierr != nil {
			return 0, false, fmt.Errorf("insert destination: %w", ierr)
		}
		id, ierr = res.LastInsertId()
		return id, true, ierr
	}

	if _, uerr := d.w.ExecContext(ctx,
		`UPDATE destinations SET last_seen = ?, contacts = contacts + ?,
		     bytes_sent = bytes_sent + ?, bytes_recv = bytes_recv + ?,
		     processes = COALESCE(?, processes)
		 WHERE id = ?`,
		ToMicros(dst.LastSeen), maxInt64(dst.Contacts, 1), dst.BytesSent, dst.BytesRecv,
		NullString(dst.Processes), id); uerr != nil {
		return 0, false, fmt.Errorf("update destination: %w", uerr)
	}
	return id, false, nil
}

// SetDestinationEnrichment stores reverse DNS and network metadata for a destination.
func (d *DB) SetDestinationEnrichment(ctx context.Context, id int64, rdns, asn, org, country string) error {
	_, err := d.w.ExecContext(ctx,
		`UPDATE destinations SET rdns = COALESCE(?, rdns), asn = COALESCE(?, asn),
		     asn_org = COALESCE(?, asn_org), country = COALESCE(?, country), enriched_at = ?
		 WHERE id = ?`,
		NullString(rdns), NullString(asn), NullString(org), NullString(country),
		ToMicros(time.Now()), id)
	return err
}

// FlagDestination marks a destination as matched by threat intelligence.
func (d *DB) FlagDestination(ctx context.Context, id int64) error {
	_, err := d.w.ExecContext(ctx, `UPDATE destinations SET flagged = 1 WHERE id = ?`, id)
	return err
}

// DestinationFilter selects stored destinations.
type DestinationFilter struct {
	Since    time.Time
	Internal *bool
	Flagged  *bool
	// NewSince returns only destinations first seen after this time.
	NewSince time.Time
	Search   string
	// OrderBy is last_seen, contacts, bytes_sent or first_seen.
	OrderBy string
	Limit   int
	Offset  int
}

// QueryDestinations returns destinations matching the filter.
func (d *DB) QueryDestinations(ctx context.Context, f DestinationFilter) ([]Destination, error) {
	q := `SELECT id, remote_ip, remote_port, protocol, first_seen, last_seen, contacts,
	             bytes_sent, bytes_recv, processes, rdns, asn, asn_org, country, enriched_at, internal, flagged
	      FROM destinations WHERE 1=1`
	var args []any
	if !f.Since.IsZero() {
		q += " AND last_seen >= ?"
		args = append(args, ToMicros(f.Since))
	}
	if !f.NewSince.IsZero() {
		q += " AND first_seen >= ?"
		args = append(args, ToMicros(f.NewSince))
	}
	if f.Internal != nil {
		q += " AND internal = ?"
		args = append(args, boolInt(*f.Internal))
	}
	if f.Flagged != nil {
		q += " AND flagged = ?"
		args = append(args, boolInt(*f.Flagged))
	}
	if f.Search != "" {
		q += ` AND (remote_ip LIKE ? ESCAPE '\' OR rdns LIKE ? ESCAPE '\' OR asn_org LIKE ? ESCAPE '\' OR processes LIKE ? ESCAPE '\')`
		like := "%" + escapeLike(f.Search) + "%"
		args = append(args, like, like, like, like)
	}
	switch f.OrderBy {
	case "contacts":
		q += " ORDER BY contacts DESC"
	case "bytes_sent":
		q += " ORDER BY bytes_sent DESC"
	case "first_seen":
		q += " ORDER BY first_seen DESC"
	default:
		q += " ORDER BY last_seen DESC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 10000 {
		limit = 10000
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query destinations: %w", err)
	}
	defer rows.Close()
	var out []Destination
	for rows.Next() {
		var (
			dst                            Destination
			first, last                    int64
			enriched                       sql.NullInt64
			procs, rdns, asn, org, country sql.NullString
			internal, flagged              int
		)
		if err := rows.Scan(&dst.ID, &dst.RemoteIP, &dst.RemotePort, &dst.Protocol, &first, &last,
			&dst.Contacts, &dst.BytesSent, &dst.BytesRecv, &procs, &rdns, &asn, &org, &country,
			&enriched, &internal, &flagged); err != nil {
			return nil, err
		}
		dst.FirstSeen, dst.LastSeen = FromMicros(first), FromMicros(last)
		dst.Processes, dst.ReverseDNS = str(procs), str(rdns)
		dst.ASN, dst.ASNOrg, dst.Country = str(asn), str(org), str(country)
		dst.EnrichedAt = scanTime(enriched)
		dst.Internal, dst.Flagged = internal != 0, flagged != 0
		out = append(out, dst)
	}
	return out, rows.Err()
}

// DestinationByEndpoint looks up a single destination.
func (d *DB) DestinationByEndpoint(ctx context.Context, ip string, port int, proto string) (Destination, bool, error) {
	list, err := d.QueryDestinations(ctx, DestinationFilter{Limit: 1, Search: ip})
	if err != nil {
		return Destination{}, false, err
	}
	for _, dst := range list {
		if dst.RemoteIP == ip && dst.RemotePort == port && dst.Protocol == proto {
			return dst, true, nil
		}
	}
	return Destination{}, false, nil
}

// InsertDestinationSample stores a per-destination traffic sample.
func (d *DB) InsertDestinationSample(ctx context.Context, ts time.Time, destID int64, sent, recv int64, conns int) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT OR REPLACE INTO destination_samples (ts, dest_id, bytes_sent, bytes_recv, connections)
		 VALUES (?,?,?,?,?)`,
		ToMicros(ts), destID, sent, recv, conns)
	return err
}

// DestinationCount returns the total number of known destinations.
func (d *DB) DestinationCount(ctx context.Context) (int64, error) {
	var n int64
	err := d.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM destinations`).Scan(&n)
	return n, err
}

// ContactFrequencies returns the contact counts of every destination, used to compute
// the rarity percentile.
func (d *DB) ContactFrequencies(ctx context.Context) ([]float64, error) {
	rows, err := d.r.QueryContext(ctx, `SELECT contacts FROM destinations WHERE internal = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var n float64
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
