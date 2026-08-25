package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UpsertInterface records or updates an interface description.
func (d *DB) UpsertInterface(ctx context.Context, i Interface) error {
	now := ToMicros(time.Now())
	_, err := d.w.ExecContext(ctx,
		`INSERT INTO interfaces (name, type, mac, mtu, speed_mbps, addresses, up, wireless, is_default, first_seen, last_seen)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET
		   type=excluded.type, mac=excluded.mac, mtu=excluded.mtu, speed_mbps=excluded.speed_mbps,
		   addresses=excluded.addresses, up=excluded.up, wireless=excluded.wireless,
		   is_default=excluded.is_default, last_seen=excluded.last_seen`,
		i.Name, NullString(i.Type), NullString(i.MAC), i.MTU, i.SpeedMbps, NullString(i.Addresses),
		boolInt(i.Up), boolInt(i.Wireless), boolInt(i.IsDefault), now, now)
	if err != nil {
		return fmt.Errorf("upsert interface %s: %w", i.Name, err)
	}
	return nil
}

// ListInterfaces returns every known interface, most recently seen first.
func (d *DB) ListInterfaces(ctx context.Context) ([]Interface, error) {
	rows, err := d.r.QueryContext(ctx,
		`SELECT name, type, mac, mtu, speed_mbps, addresses, up, wireless, is_default, first_seen, last_seen
		 FROM interfaces ORDER BY is_default DESC, last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		var (
			i                       Interface
			typ, mac, addr          sql.NullString
			mtu, speed              sql.NullInt64
			up, wireless, isDefault int
			firstSeen, lastSeen     sql.NullInt64
		)
		if err := rows.Scan(&i.Name, &typ, &mac, &mtu, &speed, &addr, &up, &wireless, &isDefault, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		i.Type, i.MAC, i.Addresses = str(typ), str(mac), str(addr)
		i.MTU, i.SpeedMbps = int(i64(mtu)), int(i64(speed))
		i.Up, i.Wireless, i.IsDefault = up != 0, wireless != 0, isDefault != 0
		i.FirstSeen, i.LastSeen = scanTime(firstSeen), scanTime(lastSeen)
		out = append(out, i)
	}
	return out, rows.Err()
}

// InsertInterfaceSample stores one interface counter sample.
func (d *DB) InsertInterfaceSample(ctx context.Context, s InterfaceSample) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT OR REPLACE INTO interface_samples
		 (ts, iface, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors,
		  rx_dropped, tx_dropped, rx_bps, tx_bps, self_rx_bps, self_tx_bps)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(s.Time), s.Interface, s.RxBytes, s.TxBytes, s.RxPackets, s.TxPackets,
		s.RxErrors, s.TxErrors, s.RxDropped, s.TxDropped, s.RxBps, s.TxBps, s.SelfRxBps, s.SelfTxBps)
	if err != nil {
		return fmt.Errorf("insert interface sample %s: %w", s.Interface, err)
	}
	return nil
}

// QueryInterfaceSamples returns samples for an interface in a window, oldest first.
func (d *DB) QueryInterfaceSamples(ctx context.Context, iface string, since, until time.Time, limit int) ([]InterfaceSample, error) {
	q := `SELECT ts, iface, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors,
	             rx_dropped, tx_dropped, rx_bps, tx_bps, self_rx_bps, self_tx_bps
	      FROM interface_samples WHERE 1=1`
	var args []any
	if iface != "" {
		q += " AND iface = ?"
		args = append(args, iface)
	}
	if !since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ToMicros(since))
	}
	if !until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, ToMicros(until))
	}
	if limit <= 0 {
		limit = 5000
	}
	q += " ORDER BY ts ASC LIMIT ?"
	args = append(args, limit)

	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query interface samples: %w", err)
	}
	defer rows.Close()
	var out []InterfaceSample
	for rows.Next() {
		var s InterfaceSample
		var ts int64
		if err := rows.Scan(&ts, &s.Interface, &s.RxBytes, &s.TxBytes, &s.RxPackets, &s.TxPackets,
			&s.RxErrors, &s.TxErrors, &s.RxDropped, &s.TxDropped, &s.RxBps, &s.TxBps,
			&s.SelfRxBps, &s.SelfTxBps); err != nil {
			return nil, err
		}
		s.Time = FromMicros(ts)
		out = append(out, s)
	}
	return out, rows.Err()
}

// InsertWiFiSample stores one wireless telemetry sample.
func (d *DB) InsertWiFiSample(ctx context.Context, s WiFiSample) error {
	_, err := d.w.ExecContext(ctx,
		`INSERT OR REPLACE INTO wifi_samples
		 (ts, iface, ssid, bssid, signal_dbm, signal_pct, link_mbps, rx_mbps, frequency_mhz, channel, band, noise_dbm)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(s.Time), s.Interface, NullString(s.SSID), NullString(s.BSSID),
		s.SignalDBM, s.SignalPct, s.LinkMbps, s.RxMbps, s.FrequencyMHz, s.Channel,
		NullString(s.Band), s.NoiseDBM)
	if err != nil {
		return fmt.Errorf("insert wifi sample %s: %w", s.Interface, err)
	}
	return nil
}

// LatestWiFiSample returns the most recent wireless sample.
func (d *DB) LatestWiFiSample(ctx context.Context) (WiFiSample, bool, error) {
	var (
		s                         WiFiSample
		ts                        int64
		ssid, bssid, bnd          sql.NullString
		sig, pct, freq, ch, noise sql.NullInt64
		link, rx                  sql.NullFloat64
	)
	err := d.r.QueryRowContext(ctx,
		`SELECT ts, iface, ssid, bssid, signal_dbm, signal_pct, link_mbps, rx_mbps,
		        frequency_mhz, channel, band, noise_dbm
		 FROM wifi_samples ORDER BY ts DESC LIMIT 1`).
		Scan(&ts, &s.Interface, &ssid, &bssid, &sig, &pct, &link, &rx, &freq, &ch, &bnd, &noise)
	if err == sql.ErrNoRows {
		return WiFiSample{}, false, nil
	}
	if err != nil {
		return WiFiSample{}, false, err
	}
	s.Time = FromMicros(ts)
	s.SSID, s.BSSID, s.Band = str(ssid), str(bssid), str(bnd)
	s.SignalDBM, s.SignalPct = int(i64(sig)), int(i64(pct))
	s.LinkMbps, s.RxMbps = f64(link), f64(rx)
	s.FrequencyMHz, s.Channel, s.NoiseDBM = int(i64(freq)), int(i64(ch)), int(i64(noise))
	return s, true, nil
}

// InsertPublicIP records a public address observation.
func (d *DB) InsertPublicIP(ctx context.Context, r PublicIPRecord) (int64, error) {
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO public_ip_history (ts, family, previous_ip, new_ip, asn, asn_org, country, iface, vpn_active, cgnat, provider)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		ToMicros(r.Time), r.Family, NullString(r.PreviousIP), r.NewIP, NullString(r.ASN),
		NullString(r.ASNOrg), NullString(r.Country), NullString(r.Interface),
		boolInt(r.VPNActive), boolInt(r.CGNAT), NullString(r.Provider))
	if err != nil {
		return 0, fmt.Errorf("insert public ip: %w", err)
	}
	return res.LastInsertId()
}

// LatestPublicIP returns the most recent record for an address family.
func (d *DB) LatestPublicIP(ctx context.Context, family string) (PublicIPRecord, bool, error) {
	var (
		r                                    PublicIPRecord
		ts                                   int64
		prev, asn, org, country, iface, prov sql.NullString
		vpn, cgnat                           int
	)
	err := d.r.QueryRowContext(ctx,
		`SELECT id, ts, family, previous_ip, new_ip, asn, asn_org, country, iface, vpn_active, cgnat, provider
		 FROM public_ip_history WHERE family = ? ORDER BY ts DESC LIMIT 1`, family).
		Scan(&r.ID, &ts, &r.Family, &prev, &r.NewIP, &asn, &org, &country, &iface, &vpn, &cgnat, &prov)
	if err == sql.ErrNoRows {
		return PublicIPRecord{}, false, nil
	}
	if err != nil {
		return PublicIPRecord{}, false, err
	}
	r.Time = FromMicros(ts)
	r.PreviousIP, r.ASN, r.ASNOrg = str(prev), str(asn), str(org)
	r.Country, r.Interface, r.Provider = str(country), str(iface), str(prov)
	r.VPNActive, r.CGNAT = vpn != 0, cgnat != 0
	return r, true, nil
}

// PublicIPHistory returns recent public IP records.
func (d *DB) PublicIPHistory(ctx context.Context, limit int) ([]PublicIPRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT id, ts, family, previous_ip, new_ip, asn, asn_org, country, iface, vpn_active, cgnat, provider
		 FROM public_ip_history ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("public ip history: %w", err)
	}
	defer rows.Close()
	var out []PublicIPRecord
	for rows.Next() {
		var (
			r                                    PublicIPRecord
			ts                                   int64
			prev, asn, org, country, iface, prov sql.NullString
			vpn, cgnat                           int
		)
		if err := rows.Scan(&r.ID, &ts, &r.Family, &prev, &r.NewIP, &asn, &org, &country, &iface, &vpn, &cgnat, &prov); err != nil {
			return nil, err
		}
		r.Time = FromMicros(ts)
		r.PreviousIP, r.ASN, r.ASNOrg = str(prev), str(asn), str(org)
		r.Country, r.Interface, r.Provider = str(country), str(iface), str(prov)
		r.VPNActive, r.CGNAT = vpn != 0, cgnat != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertRoutePath records a path measurement.
func (d *DB) InsertRoutePath(ctx context.Context, r RoutePath) (int64, error) {
	res, err := d.w.ExecContext(ctx,
		`INSERT INTO route_paths (ts, destination, hop_count, path, changed, rtt_ms, method)
		 VALUES (?,?,?,?,?,?,?)`,
		ToMicros(r.Time), r.Destination, r.HopCount, r.Path, boolInt(r.Changed), r.RTTMS, NullString(r.Method))
	if err != nil {
		return 0, fmt.Errorf("insert route path: %w", err)
	}
	return res.LastInsertId()
}

// LatestRoutePath returns the most recent path measurement for a destination.
func (d *DB) LatestRoutePath(ctx context.Context, destination string) (RoutePath, bool, error) {
	var (
		r      RoutePath
		ts     int64
		ch     int
		rtt    sql.NullFloat64
		method sql.NullString
	)
	err := d.r.QueryRowContext(ctx,
		`SELECT id, ts, destination, hop_count, path, changed, rtt_ms, method
		 FROM route_paths WHERE destination = ? ORDER BY ts DESC LIMIT 1`, destination).
		Scan(&r.ID, &ts, &r.Destination, &r.HopCount, &r.Path, &ch, &rtt, &method)
	if err == sql.ErrNoRows {
		return RoutePath{}, false, nil
	}
	if err != nil {
		return RoutePath{}, false, err
	}
	r.Time, r.Changed, r.RTTMS, r.Method = FromMicros(ts), ch != 0, f64(rtt), str(method)
	return r, true, nil
}

// RecentRoutePaths returns recent path measurements across destinations.
func (d *DB) RecentRoutePaths(ctx context.Context, limit int) ([]RoutePath, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.r.QueryContext(ctx,
		`SELECT id, ts, destination, hop_count, path, changed, rtt_ms, method
		 FROM route_paths ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoutePath
	for rows.Next() {
		var (
			r      RoutePath
			ts     int64
			ch     int
			rtt    sql.NullFloat64
			method sql.NullString
		)
		if err := rows.Scan(&r.ID, &ts, &r.Destination, &r.HopCount, &r.Path, &ch, &rtt, &method); err != nil {
			return nil, err
		}
		r.Time, r.Changed, r.RTTMS, r.Method = FromMicros(ts), ch != 0, f64(rtt), str(method)
		out = append(out, r)
	}
	return out, rows.Err()
}
