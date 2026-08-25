# Troubleshooting

Three commands answer most questions:

```bash
ipulse status                    # what iPulse currently believes
ipulse diagnostics               # which layer is at fault, with the evidence
ipulse diagnostics --privileges  # which features this host can actually run
```

`ipulse status` reads the database, so it works whether or not the service is running,
and labels a stale reading with its age.

---

## The service will not start

### Linux

```bash
systemctl status ipulse
journalctl -u ipulse -n 100 --no-pager
sudo ipulse config validate
```

**`status=203/EXEC`** — the binary is missing or not executable.

```bash
ls -l /usr/local/bin/ipulse && file /usr/local/bin/ipulse
```

**`configuration is invalid`** — validation reports every problem at once, with the key
path and the value it rejected. An invalid file is refused rather than partly applied.

**`permission denied` on the data directory** — the unit runs as `root` by default and as
`ipulse` when installed with `--user ipulse`. If ownership was changed by hand:

```bash
sudo chown -R ipulse:ipulse /var/lib/ipulse /var/log/ipulse
sudo chmod 750 /var/lib/ipulse
```

**`Failed to determine group credentials`** — the `ipulse` user in the unit no longer
exists. Recreate it or reinstall the unit with `sudo ipulse service install`.

**Started, then immediately `Deactivating`** — usually the port is taken; see below.

Run it in the foreground to see everything:

```bash
sudo ipulse run --config /etc/ipulse/ipulse.yaml
```

### Windows

```powershell
Get-Service iPulse
Get-EventLog -LogName Application -Source iPulse -Newest 40
ipulse config validate
```

**Error 1053 (did not respond in time)** — almost always a configuration error before the
service could report ready. The Event Log entry has the reason.

**Error 5 (access denied)** — the service must run as LocalSystem. Check with
`sc.exe qc iPulse`, and reinstall with `ipulse service install` from an elevated prompt.

**Error 1067** — check `C:\ProgramData\iPulse\logs\ipulse.log`; the last line before the
exit is the cause.

Run it in the foreground from an elevated prompt:

```powershell
ipulse run
```

---

## The dashboard will not open

```bash
curl -sS http://127.0.0.1:8750/api/v1/health
```

**Connection refused** — either the service is not running, or the dashboard is disabled
(`dashboard.enabled: false`), or the listener failed to bind. `ipulse status` shows the
service state; the log records a bind failure explicitly.

**Port in use** — something else holds 8750:

```bash
ss -tlnp 'sport = :8750'                                  # Linux
Get-NetTCPConnection -LocalPort 8750 | Select OwningProcess  # Windows
```

Change `dashboard.port` and restart.

**403 `host_not_allowed`** — you reached it by a name that is not in
`dashboard.allowed_hosts`. That check is the DNS-rebinding defence. Add the name you use:

```yaml
dashboard:
  allowed_hosts: ["127.0.0.1", "localhost", "[::1]", "monitor.lan"]
```

**401** — `dashboard.auth_token` is set. Send it:

```bash
curl -H "X-iPulse-Token: $TOKEN" http://127.0.0.1:8750/api/v1/status
```

**Cannot reach it from another machine** — that is the default. iPulse binds to loopback.
Prefer an SSH tunnel:

```bash
ssh -N -L 8750:127.0.0.1:8750 user@host
```

If you must bind wider, set both `dashboard.address` and a token; validation rejects one
without the other.

**The page loads but the charts are empty** — there is no data yet. Baselines and charts
need samples; check `ipulse status` and the `/api/v1/tasks` endpoint.

---

## No data is being collected

```bash
curl -s http://127.0.0.1:8750/api/v1/tasks | jq '.[] | {name, runs, failures, last_error}'
```

This is the definitive answer to "is monitoring actually running". Each task reports its
run count, failure count, last duration, last error and next run.

- `runs: 0` and a future `next_run` — it has not fired yet. Long intervals (public IP at
  5 m, speed test at 30 m, routing at 30 m) look idle at first.
- `runs: 0` with no `next_run` — the collector is disabled in configuration.
- rising `failures` with a `last_error` — the error text says which probe failed.
- rising `skips` — the previous run was still going. Increase the interval or reduce
  `probe_timeout`.

---

## Latency or packet loss is missing

```bash
ipulse test latency
ipulse diagnostics --privileges
```

ICMP needs privilege. Without it iPulse falls back to TCP connect timing and says so in
the result's `method` field. TCP timing includes handshake cost, so it reads slightly
higher than ICMP — a step change in your latency chart right after a permissions change
is usually this, not the network.

Grant ICMP without running as root:

```bash
sudo setcap cap_net_raw+ep /usr/local/bin/ipulse       # standalone binary
```

The packaged systemd unit already has `AmbientCapabilities=CAP_NET_RAW`. Note that
`setcap` is cleared by a binary replacement, so reapply it after a manual upgrade.

Linux also offers unprivileged ICMP sockets:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

**Packet loss is always 0 or always 100** — some networks drop ICMP entirely. Set
`latency.method: tcp` there; loss then reflects failed handshakes, which is still a
useful signal but not the same measurement.

---

## Process names are missing from connections

```bash
ipulse connections | head
ipulse diagnostics --privileges
```

Seeing another user's socket owner requires `CAP_DAC_READ_SEARCH` on Linux (the packaged
unit has it) or Administrator on Windows. Without it, connections are still recorded —
only the process attribution is absent. Nothing else is affected.

```bash
sudo setcap 'cap_net_raw,cap_dac_read_search+ep' /usr/local/bin/ipulse
```

---

## Wi-Fi telemetry is missing

`ipulse test` and the interfaces view show Wi-Fi only on a wireless interface. iPulse uses
nl80211 over generic netlink on Linux, falling back to wireless extensions, and the WLAN
API on Windows. If the interface is wired, or is a bridge or virtual device over a
wireless one, there is nothing to report. `wifi.enabled: false` also silences it.

---

## Speed tests fail or look wrong

```bash
ipulse test speed --json | jq '{download_mbps, upload_mbps, status, error, endpoint}'
```

**`skipped: link busy`** — the link was already carrying more than
`speed_test.skip_if_busy_mbps`. This is deliberate: measuring a contended link produces a
number that says more about the other traffic than the connection. Set it to `0` to
measure anyway.

**Results far below the plan** — check in this order:

1. Wi-Fi. `-70 dBm` or a low negotiated link rate caps throughput well below the plan.
   Test from a wired host before blaming the ISP.
2. Other traffic. `ipulse connections` and the traffic view show what else was running.
3. The endpoint. Try another: `speed_test.endpoint_selection: latency` picks the closest,
   but a congested nearby endpoint can still be slow. Add a second endpoint and compare.
4. The host itself. A single stream on a fast link can be CPU-bound; raise
   `speed_test.streams`.

**Highly variable numbers** — raise `duration` to 15–20 s. A 10 s test on a link with
bursty cross-traffic has real variance.

**HTTP 429 from an endpoint** — iPulse backs off and retries up to three times, then
records the partial result. Frequent 429s mean the interval is too aggressive for a
public endpoint; lengthen `full_interval` or host your own.

**Too much data used** — see the metered-connection section of
[configuration.md](configuration.md#speed_test). The caps are enforced immediately, so
lowering `max_download_bytes` takes effect on the next test.

---

## Too many alerts

Everything below is in [configuration.md](configuration.md); the order here is the order
worth trying.

**During the first day** — expected. Baselines need `baseline.min_observations` (30)
samples per time bucket, and destination reporting waits out
`destinations.learning_period`. iPulse is quieter on day three than on day one.

**Latency alerts on a good connection** — raise the absolute floor so small absolute
changes cannot be large relative ones:

```yaml
alerts:
  min_absolute_latency_ms: 50
  latency_degradation_percent: 150
```

**Flapping** — require more consecutive breaches and space the repeats:

```yaml
alerts:
  persistence: 4
  cooldown: 1h
```

**Traffic spikes from ordinary use** — a backup or a game download is a real spike. Raise
the threshold and the floor:

```yaml
traffic:
  spike_z_score: 8
  spike_min_mbps: 50
```

**"Possible lateral scanning behavior detected" from your own tooling** — add it to the
allow list. This is the single most valuable tuning knob for a managed network:

```yaml
lateral:
  allow_processes: [nmap, nessus-agent, ansible-*, zabbix_agentd]
```

**New-destination noise** — most of it comes from CDNs a browser touches once. Narrow it:

```yaml
destinations:
  new_destination_window: 72h
  ignore_processes: [chrome, firefox, msedge]
```

**Public IP change events** — a dynamic address is normal and iPulse records it as a
notice, not an incident. Only a change of ASN or country is treated as significant.

Whatever you change, verify what the current rules would say:

```bash
ipulse events --stats --since 7d          # what is actually firing
ipulse events --category security --since 7d
```

---

## Alerts I expected are missing

**Suppression by correlation.** When a rule concludes, the events that fed it are marked
as contributing and hidden from the default view. Show them:

```bash
ipulse events --suppressed --since 24h
```

Or set `correlation.suppress_contributing: false`.

**Cooldown.** A repeated condition is reported once per `alerts.cooldown` (15 m).

**No baseline yet.** A relative rule cannot fire before the baseline is established.
Check with `curl -s http://127.0.0.1:8750/api/v1/baselines | jq`.

**Log level.** Routine measurements are `debug` and are not written to the log files by
default. They are always in the database — `ipulse events` and the API see them
regardless.

---

## Wrong or missing history

**The chart stops partway back** — retention. Measurements are kept 30 days raw, then
downsampled to hourly aggregates for two years. Speed tests and outages are kept a year.
Adjust `database.retention`.

**A gap in the data** — the service was not running. Outages are recorded across restarts,
but nothing can be measured while the process is stopped. `journalctl -u ipulse` or the
Event Log shows the restart.

**The database is large** — check what dominates:

```bash
ipulse status --json | jq .database
```

`connections` is usually the biggest table on a busy host. Lower
`database.retention.connections_days`, or set `connections.enabled: false`.

**`database is locked`** — another process has it open. Only one agent may run against a
database; check for a stray `ipulse run` alongside the service. iPulse uses WAL with a
`busy_timeout`, so a brief overlap resolves itself; a persistent error means two writers.

---

## Configuration changes have no effect

```bash
ipulse config              # the effective configuration, secrets redacted
sudo systemctl reload ipulse
```

Thresholds, weights, correlation and log level apply on reload. Listener address and
port, database path, log directory and the monitoring intervals need a restart; the
reload event names which of those changed and were deferred.

If `ipulse config` does not show your change, you edited a different file —
`ipulse config path` prints the one in use. `--config` and `IPULSE_CONFIG` override the
default location, and the service may have been installed with an explicit `--config`.

---

## Reporting a problem

```bash
ipulse version --json
ipulse diagnostics --json
ipulse diagnostics --privileges
ipulse config                      # already redacted
ipulse events --severity warning --since 24h
journalctl -u ipulse -n 200 --no-pager     # or the Windows Event Log
```

`ipulse config` redacts secrets, and log values are sanitised, but check the output before
sharing it: destinations and process names describe your network.
