# iPulse Architecture

iPulse is a low-overhead Internet connection monitoring, network observability and
anomaly-detection agent. It runs as a native service (`iPulse Service` on Windows,
`ipulse.service` on systemd Linux), stores everything locally, and requires no cloud
account.

This document is the authoritative description of the internal design. It is written to
be read before the code.

---

## 1. Design goals and non-goals

### Goals

| # | Goal | How it is enforced in the design |
|---|------|----------------------------------|
| 1 | Low resource utilisation | Single process, one goroutine per collector, shared HTTP transports, bounded database growth, no polling loops tighter than 1 s. |
| 2 | Works offline | Every subsystem except the probes that inherently need the Internet (speed test, public IP, external reachability) functions with no network. SQLite is embedded, no external services. |
| 3 | No mandatory cloud | Threat intel is imported from local files/URLs the operator chooses. Enrichment providers are opt-in modules. |
| 4 | Local-first storage | SQLite + rotating log files under a single data root. |
| 5 | Human-readable logging | syslog-style records with a stable `IPULSE-<code> <NAME>` header and `Key=Value` body. |
| 6 | Transparent detection | Every detector is a documented, deterministic rule over stored numbers. No opaque scoring. `docs/detection-engine.md` documents each rule; the health score formula is published. |
| 7 | Cross-platform | All OS-specific code lives behind `internal/platform` interfaces; the rest of the tree is OS-agnostic. |
| 8 | Extensible providers | Speed test, public IP, enrichment and threat-intel feeds are interfaces with registries. |
| 9 | Privacy by default | Metadata only. No payload capture, no TLS interception, no telemetry. |
| 10 | Cautious language | Detectors emit `POSSIBLE_*` / `UNUSUAL_*` names and a `Confidence` field. Nothing is reported as confirmed malicious activity. |

### Non-goals for the initial release

* No traffic blocking or enforcement. iPulse observes and reports.
* No packet payload capture, no TLS interception, no per-flow deep inspection.
* No remote management plane, no multi-node aggregation (the REST API is localhost-bound).

---

## 2. Process model

iPulse is one binary, `ipulse`, with three roles selected at runtime:

```
ipulse run          -> foreground agent (developer / portable mode, container)
ipulse service run  -> agent under a service manager (systemd / Windows SCM)
ipulse <verb>       -> CLI client; talks to the running agent over the local REST API,
                       and falls back to direct read-only database access when the
                       agent is not running.
```

The agent process owns the database and the log files. CLI invocations never write to
them (except `ipulse config validate`, which only reads, and the installer paths).
This keeps SQLite single-writer, which is the only safe way to use it from multiple
processes without a lock-contention story.

```
                       +---------------------------------------------+
                       |                ipulse agent                 |
  systemd / SCM  --->  |  Service Manager  ->  Agent  ->  Scheduler  |
                       |                          |                  |
                       |        +-----------------+-------------+     |
                       |        |          collectors           |     |
                       |        +-----------------+-------------+     |
                       |                          |                  |
                       |   Bus -> Correlation -> Events -> Logging    |
                       |                  |            \             |
                       |               Baselines        SQLite        |
                       |                                  |          |
                       |                            REST API + Web   |
                       +---------------------------------------------+
                                              ^
   ipulse status / events / connections ------+  (HTTP on 127.0.0.1:8750)
```

### Concurrency model

* **Scheduler** owns all periodic work. Each task is `{name, interval, jitter, timeout, fn}`.
  Tasks run on their own goroutine; a task that is still running when its next tick
  arrives is skipped and `IPULSE-8013 SCHEDULER_TASK_SKIPPED` is logged. Every task runs
  under a `context.WithTimeout` so a hung probe can never wedge the agent.
* **Continuous collectors** (traffic sampler, connection sampler) are long-lived
  goroutines with their own tickers, because they must maintain delta state between
  samples.
* **Bus** is an in-process fan-out of `Sample` and `Event` values. It is non-blocking:
  a slow subscriber drops samples rather than back-pressuring a collector.
* **Analysis** (baseline updates, anomaly detection, correlation) is single-goroutine and
  fed from the bus. This makes detector behaviour deterministic and easy to test: given a
  sequence of samples, the emitted events are fully determined.
* **Panics** in any collector or task are recovered and reported as
  `IPULSE-9005 PANIC_RECOVERED`; the agent keeps running.

---

## 3. Module map

```
cmd/ipulse                  CLI + entry point, subcommand dispatch
internal/version            build metadata

internal/config             YAML schema, defaults, validation, path resolution
internal/events             event model, severity, the event catalog (single source of truth)
internal/logging            logger, sinks: text, JSONL, SQLite, journald/syslog, Windows Event Log
internal/database           schema, migrations, typed stores, retention

internal/platform           OS abstraction interfaces + capability probing
internal/platform/linux     /proc, /sys, netlink, wireless-extensions ioctls
internal/platform/windows   iphlpapi, wlanapi, psapi via golang.org/x/sys/windows

internal/connectivity       health probes + layered outage diagnostics + classification
internal/dns                DNS monitor (resolution time, per-server results)
internal/latency            ICMP/TCP RTT, jitter, packet loss
internal/interfaces         interface + Wi-Fi state monitor
internal/publicip           public IPv4/IPv6, ASN/VPN/CGNAT heuristics
internal/routing            path/hop monitoring (bounded traceroute)
internal/speedtest          provider abstraction, HTTP provider, statistics, historical analysis
internal/traffic            interface counter sampling, spike/upload anomaly detection
internal/network            active TCP/UDP connection collection and normalisation
internal/destinations       destination history, novelty/rarity analysis, enrichment
internal/threatintel        local IOC store, feed importers, matcher
internal/lateral            private-range scan / sweep heuristics
internal/baseline           time-aware adaptive baselines and statistics
internal/anomaly            deviation detectors over baselines
internal/correlation        multi-signal cause inference
internal/health             0-100 Internet health score
internal/agent              wiring, scheduler, shared runtime state
internal/service            service lifecycle: install/remove/start/stop, systemd + SCM
internal/security           input sanitisation, file permissions, privilege reporting
internal/api                REST API + static web serving
web/                        dashboard (vanilla JS, no external assets, go:embed)
```

Dependency direction is strictly downward: `agent` may import collectors; collectors may
import `platform`, `database`, `events`, `logging`, `config`; nothing imports `agent`.
`platform` imports nothing from iPulse except `events`/`config` types it needs.

---

## 4. Platform abstraction boundary

Everything that differs between Windows and Linux is expressed as one of these
interfaces (`internal/platform/platform.go`). A single `platform.Provider` is resolved
once at start-up; each OS package registers its implementation from an `init()` guarded
by a build tag.

```go
type Provider interface {
    Name() string
    Capabilities() Capabilities

    Interfaces() ([]Interface, error)        // link state, counters, addresses, MTU, speed
    Routes() ([]Route, error)                // routing table incl. default gateways
    Connections(opts ConnOptions) ([]Connection, error) // TCP/UDP + owning process
    Wireless() ([]WirelessLink, error)       // SSID/RSSI/link rate/channel (no credentials)
    DNSServers() ([]netip.Addr, error)       // configured resolvers
    ProcessInfo(pid int) (Process, error)    // name, exe path, user
    Hostname() (string, error)
}
```

| Concern | Linux mechanism | Windows mechanism |
|---|---|---|
| Interfaces + counters | `/sys/class/net/*/statistics/*`, `/sys/class/net/*/operstate`, `net.Interfaces()` | `GetIfTable2` (iphlpapi) |
| Routes / gateway | `/proc/net/route`, `/proc/net/ipv6_route` | `GetIpForwardTable2` (iphlpapi) |
| TCP/UDP connections | `/proc/net/{tcp,tcp6,udp,udp6}` + inode->pid via `/proc/*/fd` | `GetExtendedTcpTable` / `GetExtendedUdpTable` with `*_OWNER_PID` |
| Process identity | `/proc/<pid>/{comm,exe,status}` | `OpenProcess` + `QueryFullProcessImageNameW`, token user via `OpenProcessToken` |
| Wi-Fi | `/proc/net/wireless` + `SIOCGIWESSID`/`SIOCGIWRATE`/`SIOCGIWFREQ` ioctls | `WlanOpenHandle` + `WlanQueryInterface(wlan_intf_opcode_current_connection)` |
| Resolvers | `/etc/resolv.conf`, `resolvectl` DBus not required | `GetAdaptersAddresses` (DnsServerList) |
| Service manager | systemd unit + `sd_notify` over `NOTIFY_SOCKET` | `golang.org/x/sys/windows/svc` + SCM via `mgr` |
| Event log | journald native protocol / `/dev/log` RFC3164 | `eventlog` (registered source `iPulse`) |
| Elevation check | `geteuid() == 0`, `CAP_NET_RAW` probe | token elevation + membership check |

**No shell-outs on the hot path.** Native APIs and kernel-exported files are used
everywhere. The only optional exception is a documented fallback for Linux Wi-Fi on
kernels where wireless-extensions ioctls are unavailable, and it is disabled by default.

Unsupported operations return `platform.ErrUnsupported`; callers degrade gracefully and
log `IPULSE-8014 PRIVILEGE_LIMITED` or `IPULSE-7106 WIFI_MONITORING_UNAVAILABLE` once,
not on every cycle.

---

## 5. Data flow

```
  collectors ──► Sample ──► Bus ──┬──► Baseline Engine ──► baselines table
                                   │
                                   ├──► Anomaly Detectors ──► Event
                                   │
                                   ├──► Correlation Engine ──► Event (probable cause)
                                   │
                                   └──► measurement stores (SQLite)

  Event ──► Logging Engine ──┬──► ipulse.log      (human readable, rotated + gzip)
                             ├──► ipulse.jsonl    (structured, rotated + gzip)
                             ├──► events table    (searchable)
                             └──► journald / Windows Event Log (significant events only)
```

A **Sample** is a single numeric observation with a kind (`latency_ms`,
`download_mbps`, `tx_bytes_per_sec`, ...), a timestamp, and optional dimensions
(interface, destination, process). A **Measurement** is the persisted form.

An **Event** is a decision: something happened that a human might care about. Events are
the only thing that reach the log sinks. Raw samples go to the database only. This is
the mechanism that stops iPulse from being an alert firehose.

---

## 6. Detection pipeline

Three stages, in order, each documented in `docs/detection-engine.md`:

1. **Baselining** (`internal/baseline`). For each metric and *time bucket* (hour-of-day
   x weekday-class), maintain a rolling window plus an exponentially-weighted summary:
   count, mean, M2 (for variance), min, max and a t-digest-free reservoir for
   percentiles (p50/p90/p95/p99). Baselines are only *usable* once
   `min_observations` (default 30) samples exist for that bucket; before that,
   detectors are inert. This is what prevents day-one false positives.

2. **Anomaly detection** (`internal/anomaly`). Deterministic rules over baseline +
   current value. Two families:
   * *Relative deviation*: `(current - baseline) / baseline > threshold` with a
     configurable percentage, e.g. latency degradation at +100 %.
   * *Robust z-score*: `|current - median| / (1.4826 * MAD) > k` for metrics whose
     distribution is skewed (traffic volume, connection counts).
   Every rule requires **persistence** (N consecutive breaches) before emitting, and
   applies **hysteresis** so recovery is reported once (`PERFORMANCE_RECOVERED`), not
   flapped.

3. **Correlation** (`internal/correlation`). A small rule engine over a sliding window
   of recent events and samples. Each rule lists required conditions and produces a
   single event carrying `ProbableCause` plus the evidence that satisfied it, and it
   *suppresses* the contributing raw events from the log for the correlation window.
   Shipped rules:

   | Conditions | Conclusion |
   |---|---|
   | upload spike + latency rise + loss rise + download drop | `LOCAL_BANDWIDTH_SATURATION` |
   | gateway OK + DNS fail + external IP OK | `DNS_FAILURE` |
   | gateway OK + DNS OK + multiple endpoints unreachable | `ISP_OR_UPSTREAM_FAILURE` |
   | interface down / no link | `LOCAL_INTERFACE_FAILURE` |
   | gateway unreachable + interface up | `GATEWAY_FAILURE` |
   | Wi-Fi RSSI low + loss/latency rise + gateway RTT rise | `WIFI_DEGRADATION` |
   | public IP change + default route change + tunnel iface | `VPN_ROUTING_CHANGE` |
   | some endpoints reachable, others not | `PARTIAL_CONNECTIVITY` |

---

## 7. Outage diagnostics

When the connectivity engine sees a failed health check it escalates to the diagnostic
ladder, which tests each layer *independently and in order*, stopping at the first layer
that explains the failure:

```
LOCAL DEVICE -> NETWORK INTERFACE -> DEFAULT GATEWAY -> DNS -> ISP -> INTERNET
```

Each rung produces evidence recorded verbatim in the outage row:

| Rung | Test |
|---|---|
| Local device | agent healthy, clock sane, loopback reachable |
| Interface | link up, carrier present, non-link-local address assigned |
| Gateway | default route present, gateway ARP/ICMP/TCP reachable |
| DNS | resolve N names against configured resolvers, then against public resolvers |
| ISP | TCP/443 to multiple IP literals across different ASNs (no DNS involved) |
| Internet | HTTPS GET to multiple independent endpoints, TLS handshake completes |

The classification is a pure function of the evidence bitmap
(`connectivity.Classify(evidence) Classification`), which makes it fully unit-testable
without any network — the simulation tests in `tests/` do exactly that.

Outages are stored with start, end, duration, classification, probable cause and the
full evidence JSON, and availability percentages are computed from them.

---

## 8. Speed testing

```go
type Provider interface {
    Name() string
    Prepare(ctx context.Context, cfg Config) (Session, error)
}
type Session interface {
    Latency(ctx context.Context) (LatencySample, error)
    Download(ctx context.Context, p Params) (ThroughputSample, error)
    Upload(ctx context.Context, p Params) (ThroughputSample, error)
    Close() error
}
```

* The default provider is **generic HTTP** — any server that can serve a sized body and
  accept a POST works, so operators can point iPulse at their own infrastructure. No
  proprietary API is required or assumed.
* Endpoints are a configurable list; the engine picks by lowest TCP connect time and
  records which endpoint was used with every result.
* Measurement method: N parallel streams, a discarded warm-up (slow-start) window, then a
  measurement window bounded by **both** a duration and a byte cap so a fast link cannot
  burn a data allowance. Throughput is computed from the measurement window only, and the
  engine reports the p90 of per-slice rates alongside the mean to resist single-slice noise.
* Two tiers: a *lightweight* probe (small transfer, latency + coarse throughput) and a
  *full* test (multi-stream download + upload). Only the full test runs on the long
  interval.
* Every speed test raises a **self-traffic marker** so the traffic monitor attributes the
  bytes to iPulse and does not raise bandwidth anomalies for its own tests.

Historical analysis (`internal/speedtest/analysis.go`) computes, per hour/day/week/month:
average, median, min, max, p10/p25/p75/p90/p95, standard deviation, percentage of samples
below baseline, and percentage below the configured ISP expectation.

---

## 9. Storage

SQLite (pure-Go driver, no cgo, so the same code cross-compiles to Windows) in WAL mode
with `busy_timeout`, `synchronous=NORMAL`, and a single writer. Schema, indexes and
retention policy are in `internal/database/schema.go`; the migration runner is
version-stamped in `schema_migrations`.

Core tables: `events`, `measurements`, `speed_tests`, `outages`, `interfaces`,
`interface_samples`, `connections`, `destinations`, `destination_samples`, `baselines`,
`public_ip_history`, `routes`, `wifi_samples`, `threat_indicators`, `threat_matches`,
`config_meta`.

Retention is per-table and time-based, executed by a scheduled prune task, followed by an
incremental vacuum. Hot tables (`measurements`, `interface_samples`) additionally support
**downsampling**: rows older than the raw-retention window are rolled up into hourly
aggregates before deletion, so long-range charts survive pruning.

---

## 10. API and dashboard

`internal/api` serves both the JSON API under `/api/v1/` and the embedded dashboard at
`/`. Bound to `127.0.0.1:8750` by default. Protections: loopback-only bind, optional
bearer token, an origin/host allow-list to defeat DNS rebinding, per-client rate limiting
on the POST test endpoints, request size caps, read/write timeouts, and no CORS by default.

The dashboard is dependency-free: hand-rolled SVG charts, no CDN, no build step, embedded
with `go:embed`, so it works on an air-gapped host.

---

## 11. Security posture

* The agent needs no root/Administrator for: HTTP/TCP/DNS probes, speed tests, interface
  counters, routes, its own connections, the API and dashboard.
* Elevated rights improve: ICMP echo (raw/datagram sockets), process attribution for
  *other users'* sockets, traceroute, and Windows Event Log source registration.
* Linux packaging therefore runs the service as the dedicated `ipulse` user with only
  `CAP_NET_RAW` (ICMP/traceroute) and `CAP_DAC_READ_SEARCH` (process attribution),
  plus a hardened unit (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`,
  `ProtectHome`, `SystemCallFilter`). Windows runs as `LocalSystem` because the
  extended connection tables and WLAN API require it; the dashboard and API remain
  loopback-bound and unprivileged consumers.
* `docs/security.md` enumerates exactly which feature needs which privilege and what is
  lost without it. `ipulse diagnostics --privileges` prints the live capability report.
* All configuration input is validated before use; all log values are sanitised
  (control characters and newlines escaped) so a hostile process name or SSID cannot
  forge a log record.

---

## 12. Development phases

1. Core agent, config, service lifecycle, logging, SQLite.
2. Connectivity, gateway, DNS, latency, packet loss.
3. Speed testing and historical performance analysis.
4. Outage diagnostics and correlation.
5. Traffic and active connection monitoring.
6. Destination analysis and public-IP monitoring.
7. Baselines and anomaly detection.
8. Threat intelligence and lateral-connection detection.
9. REST API and dashboard.
10. Installers, tests, documentation.

Each phase ends with: build, `go vet`, `go test ./...`, security review of the delta.
