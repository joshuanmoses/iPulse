// Package database is the local SQLite store for every measurement, event, outage,
// connection, destination, baseline and indicator iPulse records.
//
// Concurrency model: the agent process is the only writer. A dedicated single-connection
// writer handle serialises writes (which removes lock contention entirely), and a
// separate multi-connection reader handle serves the API and CLI. WAL mode lets readers
// proceed while a write is in flight.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Pure-Go SQLite driver: no cgo, so the same source cross-compiles to Windows.
	_ "modernc.org/sqlite"
)

// DB is the iPulse local database.
type DB struct {
	w    *sql.DB // single-connection writer
	r    *sql.DB // pooled reader
	path string

	schemaVersion int
	migrations    int
}

// Options configures Open.
type Options struct {
	Path        string
	BusyTimeout time.Duration
	// ReadOnly opens the database without attempting migrations. The CLI uses this
	// so an `ipulse events` invocation can never disturb the running agent.
	ReadOnly bool
	// FileMode is applied to a newly created database file.
	FileMode os.FileMode
}

// Open opens (and if necessary creates and migrates) the database.
func Open(opts Options) (*DB, error) {
	if opts.Path == "" {
		return nil, errors.New("database: path is required")
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	if opts.FileMode == 0 {
		opts.FileMode = 0o640
	}

	if !opts.ReadOnly {
		if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
			return nil, fmt.Errorf("database: create directory: %w", err)
		}
	} else if _, err := os.Stat(opts.Path); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}

	db := &DB{path: opts.Path}

	writerDSN := dsn(opts.Path, opts.BusyTimeout, false)
	w, err := sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, fmt.Errorf("database: open writer: %w", err)
	}
	// Exactly one writer connection: SQLite allows only one anyway, and forcing it
	// here converts potential SQLITE_BUSY errors into ordinary queueing.
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	db.w = w

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := w.PingContext(ctx); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("database: connect: %w", err)
	}

	if !opts.ReadOnly {
		if err := os.Chmod(opts.Path, opts.FileMode); err != nil && !os.IsNotExist(err) {
			// Not fatal: the database is usable, but note it for the caller.
			_ = err
		}
		if err := db.migrate(ctx); err != nil {
			_ = w.Close()
			return nil, err
		}
	} else {
		v, _ := db.currentVersion(ctx)
		db.schemaVersion = v
	}

	r, err := sql.Open("sqlite", dsn(opts.Path, opts.BusyTimeout, true))
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("database: open reader: %w", err)
	}
	r.SetMaxOpenConns(4)
	r.SetMaxIdleConns(2)
	db.r = r

	return db, nil
}

// dsn builds a driver DSN. Pragmas are set per-connection through the DSN so every
// pooled connection gets them, which a one-off Exec after Open would not guarantee.
func dsn(path string, busy time.Duration, readOnly bool) string {
	q := []string{
		"_pragma=busy_timeout(" + fmt.Sprint(busy.Milliseconds()) + ")",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
		"_pragma=temp_store(MEMORY)",
		// Bounded page cache (~16 MiB): iPulse must stay a low-footprint agent.
		"_pragma=cache_size(-16384)",
	}
	if readOnly {
		q = append(q, "mode=ro")
	} else {
		// Take the write lock immediately on BEGIN so a deferred transaction cannot
		// fail late with SQLITE_BUSY after doing work.
		q = append(q, "_txlock=immediate")
	}
	return "file:" + filepath.ToSlash(path) + "?" + strings.Join(q, "&")
}

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// SchemaVersion returns the applied schema version.
func (d *DB) SchemaVersion() int { return d.schemaVersion }

// MigrationsApplied returns how many migrations ran during Open.
func (d *DB) MigrationsApplied() int { return d.migrations }

// Writer exposes the writer handle for the stores in this package.
func (d *DB) Writer() *sql.DB { return d.w }

// Reader exposes the pooled read handle.
func (d *DB) Reader() *sql.DB {
	if d.r != nil {
		return d.r
	}
	return d.w
}

// SizeBytes returns the on-disk size of the database and its WAL.
func (d *DB) SizeBytes() int64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if st, err := os.Stat(d.path + suffix); err == nil {
			total += st.Size()
		}
	}
	return total
}

// Close closes both handles, checkpointing the WAL so the main file is complete.
func (d *DB) Close() error {
	var firstErr error
	if d.w != nil {
		if _, err := d.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := d.w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.r != nil {
		if err := d.r.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// InTx runs fn inside a transaction, rolling back on error. Used for multi-row writes
// such as a connection sample or a feed import.
func (d *DB) InTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Exec runs a statement on the writer.
func (d *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.w.ExecContext(ctx, query, args...)
}

// Query runs a read query on the reader.
func (d *DB) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.r.QueryContext(ctx, query, args...)
}

// QueryRow runs a single-row read query on the reader.
func (d *DB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return d.r.QueryRowContext(ctx, query, args...)
}

// --- timestamp helpers -------------------------------------------------------
//
// Timestamps are stored as microseconds since the Unix epoch: an integer that sorts
// and ranges efficiently, keeps sub-millisecond probe resolution, and stays far from
// any 2038 problem.

// ToMicros converts a time to the stored representation.
func ToMicros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

// FromMicros converts a stored timestamp back to a time in the local zone.
func FromMicros(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).Local()
}

// NullString converts an empty string to SQL NULL, keeping indexes compact.
func NullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// NullTime converts a zero time to SQL NULL.
func NullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMicro()
}

func scanTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return FromMicros(v.Int64)
}

func str(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

func f64(v sql.NullFloat64) float64 {
	if !v.Valid {
		return 0
	}
	return v.Float64
}

func i64(v sql.NullInt64) int64 {
	if !v.Valid {
		return 0
	}
	return v.Int64
}
