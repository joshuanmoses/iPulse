package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// UpsertConnections records a batch of observed connections. A connection is keyed by
// protocol plus both endpoints plus the owning pid, so repeated samples of the same
// socket accumulate rather than creating new rows.
func (d *DB) UpsertConnections(ctx context.Context, conns []Connection) error {
	if len(conns) == 0 {
		return nil
	}
	return d.InTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO connections (conn_key, first_seen, last_seen, protocol, local_ip, local_port,
				remote_ip, remote_port, state, pid, process, exe, username,
				bytes_sent, bytes_recv, duration_ms, iface, internal, samples)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
			 ON CONFLICT(conn_key) DO UPDATE SET
			   last_seen   = excluded.last_seen,
			   state       = excluded.state,
			   bytes_sent  = MAX(connections.bytes_sent, excluded.bytes_sent),
			   bytes_recv  = MAX(connections.bytes_recv, excluded.bytes_recv),
			   duration_ms = excluded.last_seen / 1000 - connections.first_seen / 1000,
			   process     = COALESCE(excluded.process, connections.process),
			   exe         = COALESCE(excluded.exe, connections.exe),
			   username    = COALESCE(excluded.username, connections.username),
			   samples     = connections.samples + 1`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, c := range conns {
			if _, err := stmt.ExecContext(ctx, c.Key, ToMicros(c.FirstSeen), ToMicros(c.LastSeen),
				c.Protocol, NullString(c.LocalIP), c.LocalPort, NullString(c.RemoteIP), c.RemotePort,
				NullString(c.State), c.PID, NullString(c.Process), NullString(c.Exe), NullString(c.User),
				c.BytesSent, c.BytesRecv, c.Duration.Milliseconds(), NullString(c.Interface),
				boolInt(c.Internal)); err != nil {
				return fmt.Errorf("upsert connection %s: %w", c.Key, err)
			}
		}
		return nil
	})
}

// ConnectionFilter selects stored connections.
type ConnectionFilter struct {
	Since      time.Time
	Until      time.Time
	Protocol   string
	Process    string
	RemoteIP   string
	RemotePort int
	State      string
	Internal   *bool
	Search     string
	Limit      int
	Offset     int
}

// QueryConnections returns connections matching the filter, most recent first.
func (d *DB) QueryConnections(ctx context.Context, f ConnectionFilter) ([]Connection, error) {
	q := `SELECT id, conn_key, first_seen, last_seen, protocol, local_ip, local_port,
	             remote_ip, remote_port, state, pid, process, exe, username,
	             bytes_sent, bytes_recv, duration_ms, iface, internal, samples
	      FROM connections WHERE 1=1`
	var args []any
	if !f.Since.IsZero() {
		q += " AND last_seen >= ?"
		args = append(args, ToMicros(f.Since))
	}
	if !f.Until.IsZero() {
		q += " AND last_seen <= ?"
		args = append(args, ToMicros(f.Until))
	}
	if f.Protocol != "" {
		q += " AND protocol = ?"
		args = append(args, strings.ToLower(f.Protocol))
	}
	if f.Process != "" {
		q += ` AND process LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(f.Process)+"%")
	}
	if f.RemoteIP != "" {
		q += " AND remote_ip = ?"
		args = append(args, f.RemoteIP)
	}
	if f.RemotePort > 0 {
		q += " AND remote_port = ?"
		args = append(args, f.RemotePort)
	}
	if f.State != "" {
		q += " AND state = ?"
		args = append(args, strings.ToUpper(f.State))
	}
	if f.Internal != nil {
		q += " AND internal = ?"
		args = append(args, boolInt(*f.Internal))
	}
	if f.Search != "" {
		q += ` AND (process LIKE ? ESCAPE '\' OR remote_ip LIKE ? ESCAPE '\' OR exe LIKE ? ESCAPE '\')`
		like := "%" + escapeLike(f.Search) + "%"
		args = append(args, like, like, like)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 20000 {
		limit = 20000
	}
	q += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var (
			c                                    Connection
			first, last, durMS                   int64
			lip, rip, state, proc, exe, usr, ifc sql.NullString
			lport, rport, pid                    sql.NullInt64
			internal                             int
		)
		if err := rows.Scan(&c.ID, &c.Key, &first, &last, &c.Protocol, &lip, &lport,
			&rip, &rport, &state, &pid, &proc, &exe, &usr,
			&c.BytesSent, &c.BytesRecv, &durMS, &ifc, &internal, &c.Samples); err != nil {
			return nil, err
		}
		c.FirstSeen, c.LastSeen = FromMicros(first), FromMicros(last)
		c.LocalIP, c.RemoteIP, c.State = str(lip), str(rip), str(state)
		c.Process, c.Exe, c.User, c.Interface = str(proc), str(exe), str(usr), str(ifc)
		c.LocalPort, c.RemotePort, c.PID = int(i64(lport)), int(i64(rport)), int(i64(pid))
		c.Duration = time.Duration(durMS) * time.Millisecond
		c.Internal = internal != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountConnections returns the number of connections matching the filter.
func (d *DB) CountConnections(ctx context.Context, f ConnectionFilter) (int64, error) {
	f.Limit, f.Offset = 20000, 0
	conns, err := d.QueryConnections(ctx, f)
	return int64(len(conns)), err
}

// ProcessTraffic is per-process traffic attribution over a window.
type ProcessTraffic struct {
	Process     string `json:"process"`
	Connections int    `json:"connections"`
	BytesSent   int64  `json:"bytes_sent"`
	BytesRecv   int64  `json:"bytes_recv"`
}

// TopProcesses returns the processes with the most outbound bytes in a window.
func (d *DB) TopProcesses(ctx context.Context, since time.Time, limit int) ([]ProcessTraffic, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT COALESCE(process, '(unknown)'), COUNT(*), SUM(bytes_sent), SUM(bytes_recv)
		 FROM connections WHERE last_seen >= ?
		 GROUP BY process ORDER BY SUM(bytes_sent) DESC, COUNT(*) DESC LIMIT ?`,
		ToMicros(since), limit)
	if err != nil {
		return nil, fmt.Errorf("top processes: %w", err)
	}
	defer rows.Close()
	var out []ProcessTraffic
	for rows.Next() {
		var p ProcessTraffic
		var sent, recv sql.NullInt64
		if err := rows.Scan(&p.Process, &p.Connections, &sent, &recv); err != nil {
			return nil, err
		}
		p.BytesSent, p.BytesRecv = i64(sent), i64(recv)
		out = append(out, p)
	}
	return out, rows.Err()
}
