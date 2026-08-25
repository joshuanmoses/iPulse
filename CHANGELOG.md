# Changelog

All notable changes to iPulse are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and iPulse uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-24

First release. iPulse runs as a real service on Windows 10/11, Windows Server 2019+ and
systemd Linux, starts at boot with no interactive session, and monitors an Internet
connection continuously without saturating it.

### Connection monitoring

- Reachability checks every 15 seconds against a diverse target set, with a six-rung
  diagnostic ladder — local device, interface, gateway, DNS, ISP path, Internet — that
  reports which layer is at fault and shows the evidence for the conclusion.
- Outage detection with hysteresis, classification (ISP outage, DNS failure, gateway
  failure, local interface failure, routing failure, captive portal, Wi-Fi degradation,
  partial connectivity), and availability accounting including MTBF and the longest
  outage in a window.
- Latency, jitter and packet loss every 30 seconds over unprivileged ICMP where it is
  permitted and TCP connect timing where it is not, with the method recorded alongside
  every result. Gateway round-trip is measured separately, which is what separates a
  local problem from an upstream one.
- DNS resolution timing across the system resolvers, one name per cycle, with fallback
  resolvers queried only during diagnosis.
- Public IPv4 and IPv6 discovery with ASN and ISP lookup, change confirmation across two
  providers, and CGNAT and VPN detection. ASN lookup uses DNS by default, so no HTTP
  service and no API key is involved.
- Path measurement (traceroute) using the IP error queue, so a full path is measured
  without raw-socket privilege on Linux.
- Interface, route, resolver and Wi-Fi tracking, including nl80211 telemetry on kernels
  without wireless extensions.

### Throughput

- A lightweight probe every 5 minutes and a full multi-stream test every 30 minutes, both
  configurable, with hard byte caps enforced the instant they are reached, a busy-link
  skip, warm-up discard and TTFB-based latency on a reused connection.
- Provider abstraction with a plain HTTP implementation: any server that serves a sized
  body and accepts a POST works, including your own. There is no dependency on a
  commercial speed-test API.
- Plan comparison and shortfall reporting when `speed_test.expected_*_mbps` is set.

### Network observability

- Continuous interface counter sampling with rate, error and drop tracking, and honest
  exclusion of iPulse's own test traffic so a speed test never raises an anomaly about
  itself.
- Socket-table collection with process attribution where privilege allows, degrading to
  unattributed connections rather than failing.
- Destination profiling: first and last contact, volume, port profile, reverse DNS, and
  new, rare, high-volume and fan-out analysis with a learning period before anything is
  reported.
- Threat intelligence from any number of feeds in plain, hosts, CSV or JSON form, local
  or remote, with conditional fetching, expiry and an allow list. No vendor is
  hard-coded, and no feed is configured by default.
- Lateral-movement heuristics — host sweeps, port scans, failed-connection bursts and
  administrative-port sweeps — with confidence grading and an allow list for approved
  scanners.

### Detection

- Baselines learned per metric and per time bucket using Welford accumulators, EWMA and
  median/MAD, with a minimum observation count, a learning period and an aggregate
  fallback so a new installation is quiet on its first day.
- Robust z-score and relative-deviation rules with absolute floors, so a 5 ms baseline
  rising to 12 ms is not reported as a 140 % degradation.
- A persistence, cooldown and recovery gate on every rule, which is what stops flapping.
- Event correlation that turns several simultaneous events into one conclusion and marks
  the contributing events as absorbed, while the log files keep every raw record.
- A weighted health score with configurable weights and thresholds; components without
  measurements are excluded and their weight redistributed.

### Interfaces

- A local REST API and a dashboard with nine views: overview, connection, performance,
  traffic, connections, destinations, security, events and diagnostics. Vanilla
  JavaScript with hand-drawn SVG charts, embedded in the binary, with no external
  requests and no build step.
- A full command line: `status`, `events` (including `--follow` and the event catalog),
  `connections`, `destinations`, `test`, `diagnostics`, `config`, `service`, `run` and
  `version`, all with `--json`.
- 115+ catalogued events with reserved ID ranges, each with a documented severity,
  category, trigger, field set and suggested action, emitted as syslog-style text, JSON
  Lines, database rows, journald records and Windows Event Log entries.

### Platforms

- Linux: netlink, `/proc/net/*`, `/sys/class/net`, nl80211 over generic netlink, inode to
  PID mapping, and the `IP_RECVERR` error queue. A hardened `Type=notify` unit with
  `sd_notify` implemented natively, `ProtectSystem=strict`, and only `CAP_NET_RAW` and
  `CAP_DAC_READ_SEARCH`.
- Windows: `iphlpapi`, `wlanapi`, the extended TCP and UDP tables, the service control
  manager and the Event Log, with delayed automatic start and recovery actions.
- Every OS-specific mechanism sits behind one `platform.Provider` interface. All four
  targets cross-compile with `CGO_ENABLED=0`, including SQLite, so each platform gets a
  single static binary.

### Packaging

- `.deb` and `.rpm` packages, an MSI built with WiX v4, and shell and PowerShell
  installers. Every path registers the same service definition the binary itself
  produces, so a packaged installation and a manual one cannot diverge. Configuration is
  marked as a config file in both Linux formats, and no removal path deletes collected
  data without an explicit purge.

### Security and privacy

- Metadata only. No payload inspection, no TLS interception, no HTTP bodies, no
  credentials, no keystrokes.
- No cloud telemetry, no analytics, no tracking. Nothing is contacted except the
  measurement endpoints, resolvers and threat feeds in your own configuration.
- The dashboard binds to loopback; binding anywhere else requires a token, which is
  compared in constant time. A Host allow-list defeats DNS rebinding, and no CORS header
  is ever emitted.
- Every configuration value is validated before it is applied, log values are sanitised,
  files are created with restrictive permissions, and no collector shells out.
- No traffic is blocked automatically, and no detection asserts compromise. Findings are
  reported as possibilities with their evidence and a confidence grade.

[1.0.0]: https://github.com/ipulse/ipulse/releases/tag/v1.0.0
