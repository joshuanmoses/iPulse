# REST API

iPulse serves a JSON API and the dashboard from the same local HTTP server.

```text
http://127.0.0.1:8750/api/v1/
```

Bound to loopback by default. Binding elsewhere requires `dashboard.auth_token` and is
rejected by configuration validation without it.

## Authentication

None by default, because the listener is loopback-only. When `dashboard.auth_token` is
set, every request must carry it:

```bash
curl -H "X-iPulse-Token: $TOKEN" http://127.0.0.1:8750/api/v1/status
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8750/api/v1/status
```

Tokens are compared in constant time and must be at least 16 characters.

## Protections

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and a strict `Content-Security-Policy`. No CORS header is
ever emitted.

The `Host` header must appear in `dashboard.allowed_hosts` (`127.0.0.1`, `localhost` and
`[::1]` by default) or the request is refused with 403 `host_not_allowed`. This is what
makes a loopback API safe against DNS rebinding.

## Errors

```json
{
  "error": "Bad Request",
  "code": "bad_severity",
  "message": "unknown severity \"bogus\""
}
```

| Status | Meaning |
|---|---|
| 400 | invalid parameter; `code` and `message` say which |
| 401 | a token is required or was wrong |
| 403 | Host not allowed, or a remote client attempted a test |
| 404 | unknown endpoint, or a task that is not registered |
| 405 | wrong method; the `Allow` header names the right one |
| 429 | rate limited; `Retry-After` says how long |
| 500 | a query failed; `message` has the detail |

## Common parameters

| Parameter | Meaning |
|---|---|
| `since` | a window (`30m`, `6h`, `7d`, `2w`, `3mo`, `1y`) or an RFC 3339 timestamp |
| `until` | RFC 3339 upper bound |
| `limit` | maximum rows; clamped per endpoint |
| `offset` | pagination offset |

`m` means minutes, as it does everywhere else; months are written `mo`.

---

## Status and health

### `GET /api/v1/status`

The agent's complete current view: link status, health score and components, latency,
jitter, loss, DNS, throughput, current rates, public addresses, ASN and ISP, interface,
gateway, VPN state, Wi-Fi association, current outage, availability, counters, platform
capabilities and uptime.

```bash
curl -s http://127.0.0.1:8750/api/v1/status | jq '{status, health_score, latency_ms, public_ipv4}'
```

### `GET /api/v1/health`

The health score with its components, the effective weights and the formula that produced
it. Also serves as a liveness probe.

```json
{
  "score": 94.2,
  "components": {"availability": 100, "latency": 91.1, "packet_loss": 100, "download": 97.4},
  "weights": {"availability": 30, "latency": 20, "packet_loss": 12, "download": 15},
  "status": "ONLINE",
  "online": true,
  "warn_below": 70,
  "scoring": "score = sum(weight_i * component_i) / sum(weight_i); …"
}
```

### `GET /api/v1/summary`

Everything the dashboard's overview needs in one request: status, last speed test, 24-hour
availability, the day's speed analysis, event counts by severity, recent events, row
counts and scheduler statistics.

---

## Speed

### `GET /api/v1/speed`

Parameters: `mode` (`full`, `lightweight`, `manual`), `since`, `limit`.

```json
{
  "latest": {"time": "…", "download_mbps": 487.2, "upload_mbps": 41.8, "latency_ms": 18.6,
             "jitter_ms": 2.9, "endpoint": "cloudflare", "status": "ok"},
  "tests": [ … ],
  "expected_download_mbps": 500,
  "expected_upload_mbps": 50
}
```

### `GET /api/v1/speed/history`

The hour, day, week and month analysis: count, mean, median, min, max, p10/p25/p75/p90/p95,
standard deviation, percentage below the window median and percentage below your plan, for
download, upload, latency, jitter and loss.

---

## Measurements

### `GET /api/v1/measurements?metric=<name>`

Parameters: `metric` (required), `target`, `since`, `bucket_seconds`.

Returns a bucketed series plus summary statistics. Raw rows and hourly roll-ups are
combined, so a long window still has data after retention has pruned the detail.

```bash
curl -s "http://127.0.0.1:8750/api/v1/measurements?metric=latency_ms&since=6h&bucket_seconds=120"
```

Metrics: `latency_ms`, `jitter_ms`, `packet_loss_pct`, `gateway_rtt_ms`, `dns_ms`,
`download_mbps`, `upload_mbps`, `light_download_mbps`, `tcp_connect_ms`, `https_ttfb_ms`,
`rx_bps`, `tx_bps`, `rx_bytes_window`, `tx_bytes_window`, `connection_count`,
`distinct_destinations`, `wifi_signal_dbm`, `wifi_link_mbps`, `health_score`,
`availability_pct`, `hop_count`.

---

## Events

### `GET /api/v1/events`

| Parameter | Meaning |
|---|---|
| `severity` | minimum severity; add `exact=true` for that level only |
| `code` | comma-separated event IDs |
| `name` | comma-separated event names |
| `category` | comma-separated categories |
| `process`, `destination` | substring match on those dimensions |
| `q` | free-text search across the rendered record |
| `include_suppressed` | include events absorbed by a correlation rule |
| `since`, `until`, `limit`, `offset` | as above |

```bash
curl -s "http://127.0.0.1:8750/api/v1/events?severity=warning&since=24h&limit=50"
curl -s "http://127.0.0.1:8750/api/v1/events?code=3001,3004&since=7d"
curl -s "http://127.0.0.1:8750/api/v1/events?category=SECURITY&since=7d"
```

```json
{
  "events": [{
    "id": 4821,
    "time": "2026-08-24T15:04:11-05:00",
    "code": 3001,
    "name": "INTERNET_CONNECTIVITY_LOST",
    "severity": "ERROR",
    "category": "AVAILABILITY",
    "fields": {"GatewayReachable": "true", "DNSReachable": "true",
               "ExternalIPReachable": "false", "ProbableCause": "ISP_OUTAGE"},
    "rendered": "2026-08-24T15:04:11-05:00 ERROR IPULSE-3001 …"
  }],
  "total": 1,
  "by_severity": {"ERROR": 1, "WARNING": 12, "NOTICE": 4}
}
```

### `GET /api/v1/events/catalog`

Every event iPulse can emit, with severity, category, meaning, trigger, documented fields
and the suggested operator action. This is the same data as
[event-catalog.md](event-catalog.md), which is generated from it.

---

## Availability

### `GET /api/v1/outages`

Parameters: `since`, `limit`.

Returns the outage records, the availability summary for the window (percentage,
downtime, count, longest, MTBF, breakdown by cause) and the current outage if one is open.

---

## Traffic and connections

### `GET /api/v1/traffic`

Parameters: `interface`, `since`, `limit`. Returns interface samples (absolute counters,
rates, and the portion attributable to iPulse's own tests) plus the current rate.

### `GET /api/v1/connections`

Parameters: `protocol`, `process`, `remote_ip`, `remote_port`, `state`, `internal`, `q`,
`since`, `limit`, `offset`. Returns connections plus per-process totals.

### `GET /api/v1/destinations`

Parameters: `q`, `order` (`last_seen`, `contacts`, `bytes_sent`, `first_seen`),
`internal`, `flagged`, `new_since`, `since`, `limit`, `offset`.

### `GET /api/v1/threats`

Threat-intelligence matches, the indicator count by source, and per-feed import status.

---

## Network state

### `GET /api/v1/interfaces`

Known interfaces with type, addresses, link speed, state and which carries the default
route, plus the most recent Wi-Fi sample.

### `GET /api/v1/public-ip`

Current IPv4 and IPv6 addresses with ASN, organisation, country, CGNAT and VPN state, plus
the change history.

### `GET /api/v1/routes`

Recent path measurements: hop count, the full path, round trip and whether it changed.

---

## Introspection

### `GET /api/v1/config`

The effective configuration with secrets redacted, and the path it came from.

### `GET /api/v1/tasks`

Scheduler statistics: interval, runs, failures, skips, last run, last duration, last error
and next run. This is how you confirm monitoring is actually running.

### `GET /api/v1/privileges`

The privilege matrix for this host: each feature, whether it is available, what it
requires and what the fallback is.

### `GET /api/v1/baselines`

Every learned baseline, optionally filtered by `metric`: sample count, mean, median, MAD,
percentiles and whether it is established.

---

## Tests

All test endpoints are `POST`, rate limited by `dashboard.rate_limit_per_minute` (10 per
minute per client), and refused for non-loopback clients unless
`dashboard.allow_remote_tests` is set. They start real network activity.

| Endpoint | Runs |
|---|---|
| `POST /api/v1/tests/speed` | a full speed test |
| `POST /api/v1/tests/connectivity` | the reachability probes |
| `POST /api/v1/tests/dns` | a DNS probe cycle |
| `POST /api/v1/tests/latency` | a latency and loss cycle |
| `POST /api/v1/tests/traceroute` | a path measurement |
| `POST /api/v1/tests/public-ip` | public address discovery |
| `POST /api/v1/diagnostics` | the full diagnostic ladder |

```bash
curl -s -X POST http://127.0.0.1:8750/api/v1/tests/speed | jq '{ok, duration}'
```

```json
{"test": "speed", "task": "speedtest-manual", "duration": "12.4s", "ok": true, "status": { … }}
```

A 404 means the collector is disabled in configuration, so the task is not registered.

---

## Scripting

```bash
# Alert when the health score drops
score=$(curl -s http://127.0.0.1:8750/api/v1/health | jq -r .score)
(( $(echo "$score < 70" | bc -l) )) && echo "iPulse health $score"

# Yesterday's availability
curl -s "http://127.0.0.1:8750/api/v1/outages?since=24h" | jq .availability

# Every error today
curl -s "http://127.0.0.1:8750/api/v1/events?severity=error&since=24h" |
  jq -r '.events[] | "\(.time) \(.name) \(.fields.ProbableCause // "")"'

# Export speed history as CSV
curl -s "http://127.0.0.1:8750/api/v1/speed?since=30d&limit=1000" |
  jq -r '.tests[] | [.time, .download_mbps, .upload_mbps, .latency_ms] | @csv'
```

The CLI produces the same data with `--json` and works without the API:

```bash
ipulse status --json
ipulse events --severity warning --json
```
