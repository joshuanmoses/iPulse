package database

import (
	"context"
	"fmt"
	"time"
)

// migration is one forward-only schema step. Migrations are append-only: an existing
// entry is never edited, because installed agents have already applied it.
type migration struct {
	Version     int
	Description string
	Statements  []string
}

// migrations is the ordered schema history.
var migrations = []migration{
	{
		Version:     1,
		Description: "initial schema",
		Statements: []string{
			// --- events ---------------------------------------------------------
			`CREATE TABLE IF NOT EXISTS events (
				id             INTEGER PRIMARY KEY AUTOINCREMENT,
				ts             INTEGER NOT NULL,
				code           INTEGER NOT NULL,
				name           TEXT    NOT NULL,
				severity       INTEGER NOT NULL,
				category       TEXT    NOT NULL,
				message        TEXT,
				process        TEXT,
				destination    TEXT,
				correlation_id TEXT,
				suppressed     INTEGER NOT NULL DEFAULT 0,
				fields         TEXT    NOT NULL DEFAULT '{}',
				rendered       TEXT    NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_code_ts ON events(code, ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_sev_ts ON events(severity, ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_cat_ts ON events(category, ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_process ON events(process) WHERE process IS NOT NULL`,
			`CREATE INDEX IF NOT EXISTS idx_events_dest ON events(destination) WHERE destination IS NOT NULL`,
			`CREATE INDEX IF NOT EXISTS idx_events_corr ON events(correlation_id) WHERE correlation_id IS NOT NULL`,

			// --- measurements ---------------------------------------------------
			`CREATE TABLE IF NOT EXISTS measurements (
				id     INTEGER PRIMARY KEY AUTOINCREMENT,
				ts     INTEGER NOT NULL,
				metric TEXT    NOT NULL,
				value  REAL    NOT NULL,
				unit   TEXT,
				target TEXT    NOT NULL DEFAULT '',
				ok     INTEGER NOT NULL DEFAULT 1,
				meta   TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_meas_metric_ts ON measurements(metric, ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_meas_ts ON measurements(ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_meas_metric_target_ts ON measurements(metric, target, ts DESC)`,

			// Hourly roll-ups keep long-range charts alive after raw rows are pruned.
			`CREATE TABLE IF NOT EXISTS measurement_hourly (
				bucket  INTEGER NOT NULL,
				metric  TEXT    NOT NULL,
				target  TEXT    NOT NULL DEFAULT '',
				samples INTEGER NOT NULL,
				sum     REAL    NOT NULL,
				sumsq   REAL    NOT NULL,
				min     REAL    NOT NULL,
				max     REAL    NOT NULL,
				p50     REAL,
				p95     REAL,
				PRIMARY KEY (bucket, metric, target)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_meas_hourly_metric ON measurement_hourly(metric, bucket DESC)`,

			// --- speed tests ----------------------------------------------------
			`CREATE TABLE IF NOT EXISTS speed_tests (
				id                     INTEGER PRIMARY KEY AUTOINCREMENT,
				ts                     INTEGER NOT NULL,
				mode                   TEXT    NOT NULL,
				provider               TEXT,
				endpoint               TEXT,
				endpoint_location      TEXT,
				download_mbps          REAL,
				upload_mbps            REAL,
				download_p90_mbps      REAL,
				upload_p90_mbps        REAL,
				latency_ms             REAL,
				jitter_ms              REAL,
				packet_loss_pct        REAL,
				tcp_connect_ms         REAL,
				dns_ms                 REAL,
				ttfb_ms                REAL,
				bytes_down             INTEGER,
				bytes_up               INTEGER,
				streams                INTEGER,
				duration_ms            INTEGER,
				status                 TEXT,
				error                  TEXT,
				expected_download_mbps REAL,
				expected_upload_mbps   REAL,
				iface                  TEXT,
				public_ip              TEXT,
				isp                    TEXT,
				raw                    TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_speed_ts ON speed_tests(ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_speed_mode_ts ON speed_tests(mode, ts DESC)`,

			// --- outages --------------------------------------------------------
			`CREATE TABLE IF NOT EXISTS outages (
				id                INTEGER PRIMARY KEY AUTOINCREMENT,
				started_at        INTEGER NOT NULL,
				ended_at          INTEGER,
				duration_ms       INTEGER,
				classification    TEXT    NOT NULL,
				probable_cause    TEXT,
				evidence          TEXT,
				iface             TEXT,
				gateway           TEXT,
				public_ip         TEXT,
				resolved          INTEGER NOT NULL DEFAULT 0,
				diagnostics_count INTEGER NOT NULL DEFAULT 1
			)`,
			`CREATE INDEX IF NOT EXISTS idx_outages_started ON outages(started_at DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_outages_open ON outages(resolved, started_at DESC)`,

			// --- interfaces -----------------------------------------------------
			`CREATE TABLE IF NOT EXISTS interfaces (
				name       TEXT PRIMARY KEY,
				type       TEXT,
				mac        TEXT,
				mtu        INTEGER,
				speed_mbps INTEGER,
				addresses  TEXT,
				up         INTEGER NOT NULL DEFAULT 0,
				wireless   INTEGER NOT NULL DEFAULT 0,
				is_default INTEGER NOT NULL DEFAULT 0,
				first_seen INTEGER,
				last_seen  INTEGER
			)`,
			`CREATE TABLE IF NOT EXISTS interface_samples (
				ts          INTEGER NOT NULL,
				iface       TEXT    NOT NULL,
				rx_bytes    INTEGER NOT NULL DEFAULT 0,
				tx_bytes    INTEGER NOT NULL DEFAULT 0,
				rx_packets  INTEGER NOT NULL DEFAULT 0,
				tx_packets  INTEGER NOT NULL DEFAULT 0,
				rx_errors   INTEGER NOT NULL DEFAULT 0,
				tx_errors   INTEGER NOT NULL DEFAULT 0,
				rx_dropped  INTEGER NOT NULL DEFAULT 0,
				tx_dropped  INTEGER NOT NULL DEFAULT 0,
				rx_bps      REAL    NOT NULL DEFAULT 0,
				tx_bps      REAL    NOT NULL DEFAULT 0,
				self_rx_bps REAL    NOT NULL DEFAULT 0,
				self_tx_bps REAL    NOT NULL DEFAULT 0,
				PRIMARY KEY (ts, iface)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_ifsamples_iface_ts ON interface_samples(iface, ts DESC)`,
			`CREATE TABLE IF NOT EXISTS wifi_samples (
				ts            INTEGER NOT NULL,
				iface         TEXT    NOT NULL,
				ssid          TEXT,
				bssid         TEXT,
				signal_dbm    INTEGER,
				signal_pct    INTEGER,
				link_mbps     REAL,
				rx_mbps       REAL,
				frequency_mhz INTEGER,
				channel       INTEGER,
				band          TEXT,
				noise_dbm     INTEGER,
				PRIMARY KEY (ts, iface)
			)`,

			// --- connections and destinations -----------------------------------
			`CREATE TABLE IF NOT EXISTS connections (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				conn_key    TEXT    NOT NULL UNIQUE,
				first_seen  INTEGER NOT NULL,
				last_seen   INTEGER NOT NULL,
				protocol    TEXT    NOT NULL,
				local_ip    TEXT,
				local_port  INTEGER,
				remote_ip   TEXT,
				remote_port INTEGER,
				state       TEXT,
				pid         INTEGER,
				process     TEXT,
				exe         TEXT,
				username    TEXT,
				bytes_sent  INTEGER NOT NULL DEFAULT 0,
				bytes_recv  INTEGER NOT NULL DEFAULT 0,
				duration_ms INTEGER NOT NULL DEFAULT 0,
				iface       TEXT,
				internal    INTEGER NOT NULL DEFAULT 0,
				samples     INTEGER NOT NULL DEFAULT 1
			)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections(last_seen DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_remote ON connections(remote_ip, remote_port)`,
			`CREATE INDEX IF NOT EXISTS idx_conn_process ON connections(process)`,
			`CREATE TABLE IF NOT EXISTS destinations (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				remote_ip   TEXT    NOT NULL,
				remote_port INTEGER NOT NULL,
				protocol    TEXT    NOT NULL,
				first_seen  INTEGER NOT NULL,
				last_seen   INTEGER NOT NULL,
				contacts    INTEGER NOT NULL DEFAULT 0,
				bytes_sent  INTEGER NOT NULL DEFAULT 0,
				bytes_recv  INTEGER NOT NULL DEFAULT 0,
				processes   TEXT,
				rdns        TEXT,
				asn         TEXT,
				asn_org     TEXT,
				country     TEXT,
				enriched_at INTEGER,
				internal    INTEGER NOT NULL DEFAULT 0,
				flagged     INTEGER NOT NULL DEFAULT 0,
				UNIQUE (remote_ip, remote_port, protocol)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_dest_last_seen ON destinations(last_seen DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_dest_contacts ON destinations(contacts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_dest_ip ON destinations(remote_ip)`,
			`CREATE TABLE IF NOT EXISTS destination_samples (
				ts          INTEGER NOT NULL,
				dest_id     INTEGER NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
				bytes_sent  INTEGER NOT NULL DEFAULT 0,
				bytes_recv  INTEGER NOT NULL DEFAULT 0,
				connections INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (ts, dest_id)
			)`,

			// --- baselines ------------------------------------------------------
			`CREATE TABLE IF NOT EXISTS baselines (
				metric      TEXT    NOT NULL,
				dimension   TEXT    NOT NULL DEFAULT '',
				bucket      TEXT    NOT NULL DEFAULT '',
				samples     INTEGER NOT NULL DEFAULT 0,
				mean        REAL    NOT NULL DEFAULT 0,
				m2          REAL    NOT NULL DEFAULT 0,
				min         REAL,
				max         REAL,
				ewma        REAL,
				median      REAL,
				mad         REAL,
				p10         REAL,
				p25         REAL,
				p75         REAL,
				p90         REAL,
				p95         REAL,
				p99         REAL,
				reservoir   TEXT,
				established INTEGER NOT NULL DEFAULT 0,
				first_seen  INTEGER,
				updated_at  INTEGER,
				PRIMARY KEY (metric, dimension, bucket)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric)`,

			// --- public IP and routing ------------------------------------------
			`CREATE TABLE IF NOT EXISTS public_ip_history (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          INTEGER NOT NULL,
				family      TEXT    NOT NULL,
				previous_ip TEXT,
				new_ip      TEXT    NOT NULL,
				asn         TEXT,
				asn_org     TEXT,
				country     TEXT,
				iface       TEXT,
				vpn_active  INTEGER NOT NULL DEFAULT 0,
				cgnat       INTEGER NOT NULL DEFAULT 0,
				provider    TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_pubip_ts ON public_ip_history(ts DESC)`,
			`CREATE TABLE IF NOT EXISTS route_paths (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          INTEGER NOT NULL,
				destination TEXT    NOT NULL,
				hop_count   INTEGER NOT NULL,
				path        TEXT    NOT NULL,
				changed     INTEGER NOT NULL DEFAULT 0,
				rtt_ms      REAL,
				method      TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_routes_dest_ts ON route_paths(destination, ts DESC)`,

			// --- threat intelligence --------------------------------------------
			`CREATE TABLE IF NOT EXISTS threat_indicators (
				id             INTEGER PRIMARY KEY AUTOINCREMENT,
				indicator      TEXT    NOT NULL,
				kind           TEXT    NOT NULL,
				source         TEXT    NOT NULL,
				confidence     TEXT    NOT NULL DEFAULT 'medium',
				note           TEXT,
				ip_lo          BLOB,
				ip_hi          BLOB,
				first_imported INTEGER NOT NULL,
				last_in_feed   INTEGER NOT NULL,
				UNIQUE (indicator, kind, source)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator)`,
			`CREATE INDEX IF NOT EXISTS idx_ti_kind ON threat_indicators(kind)`,
			`CREATE INDEX IF NOT EXISTS idx_ti_range ON threat_indicators(ip_lo, ip_hi)`,
			`CREATE TABLE IF NOT EXISTS threat_matches (
				id             INTEGER PRIMARY KEY AUTOINCREMENT,
				ts             INTEGER NOT NULL,
				indicator      TEXT    NOT NULL,
				indicator_kind TEXT    NOT NULL,
				source         TEXT    NOT NULL,
				confidence     TEXT    NOT NULL,
				remote_ip      TEXT,
				remote_port    INTEGER,
				protocol       TEXT,
				domain         TEXT,
				pid            INTEGER,
				process        TEXT,
				exe            TEXT,
				username       TEXT,
				bytes_sent     INTEGER,
				bytes_recv     INTEGER,
				event_id       INTEGER
			)`,
			`CREATE INDEX IF NOT EXISTS idx_tm_ts ON threat_matches(ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_tm_ip ON threat_matches(remote_ip)`,
			`CREATE TABLE IF NOT EXISTS threat_feeds (
				name         TEXT PRIMARY KEY,
				last_import  INTEGER,
				last_success INTEGER,
				indicators   INTEGER NOT NULL DEFAULT 0,
				last_error   TEXT,
				etag         TEXT
			)`,

			// --- agent state / configuration metadata ---------------------------
			`CREATE TABLE IF NOT EXISTS agent_state (
				key        TEXT PRIMARY KEY,
				value      TEXT NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS config_meta (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          INTEGER NOT NULL,
				path        TEXT,
				checksum    TEXT,
				version     TEXT,
				warnings    TEXT,
				applied     INTEGER NOT NULL DEFAULT 1
			)`,
			`CREATE INDEX IF NOT EXISTS idx_config_meta_ts ON config_meta(ts DESC)`,
		},
	},
}

// SchemaVersionLatest is the newest schema version this build knows about.
func SchemaVersionLatest() int {
	if len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].Version
}

func (d *DB) currentVersion(ctx context.Context) (int, error) {
	if _, err := d.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version     INTEGER PRIMARY KEY,
		applied_at  INTEGER NOT NULL,
		description TEXT
	)`); err != nil {
		return 0, err
	}
	var v *int
	if err := d.w.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	if v == nil {
		return 0, nil
	}
	return *v, nil
}

// migrate applies every pending migration inside its own transaction, so a failure
// leaves the database at the last complete version rather than half-migrated.
func (d *DB) migrate(ctx context.Context) error {
	cur, err := d.currentVersion(ctx)
	if err != nil {
		return fmt.Errorf("database: read schema version: %w", err)
	}
	for _, m := range migrations {
		if m.Version <= cur {
			continue
		}
		tx, err := d.w.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("database: begin migration %d: %w", m.Version, err)
		}
		for i, stmt := range m.Statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("database: migration %d statement %d failed: %w", m.Version, i+1, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)`,
			m.Version, time.Now().UnixMicro(), m.Description); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("database: record migration %d: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("database: commit migration %d: %w", m.Version, err)
		}
		d.migrations++
		cur = m.Version
	}
	d.schemaVersion = cur
	return nil
}
