package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// SetState stores an agent state value. Used for small pieces of cross-restart state
// such as "when did we last import feeds" or "what was the last known public IP".
func (d *DB) SetState(ctx context.Context, key, value string) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO agent_state (key, value, updated_at) VALUES (?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, ToMicros(time.Now()))
	return err
}

// GetState reads an agent state value.
func (d *DB) GetState(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := d.r.QueryRowContext(ctx, `SELECT value FROM agent_state WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetStateJSON stores a JSON-encoded value.
func (d *DB) SetStateJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.SetState(ctx, key, string(b))
}

// GetStateJSON reads a JSON-encoded value. A missing key is not an error.
func (d *DB) GetStateJSON(ctx context.Context, key string, out any) (bool, error) {
	s, ok, err := d.GetState(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return false, err
	}
	return true, nil
}

// RecordConfig stores configuration metadata so the history of applied configurations
// is auditable.
func (d *DB) RecordConfig(ctx context.Context, path, checksum, version, warnings string, applied bool) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO config_meta (ts, path, checksum, version, warnings, applied) VALUES (?,?,?,?,?,?)`,
		ToMicros(time.Now()), NullString(path), NullString(checksum), NullString(version),
		NullString(warnings), boolInt(applied))
	return err
}
