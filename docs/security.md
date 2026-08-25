# Security

This document covers three things: what privileges iPulse needs and what each one buys,
how the agent is hardened, and what iPulse deliberately does not do.

## Privilege matrix

`ipulse diagnostics --privileges` prints this table for the machine you are on, including
what is currently unavailable and why. The same data is at `GET /api/v1/privileges`.

| Function | Linux requirement | Windows requirement | Without it |
|---|---|---|---|
| Connectivity, DNS and HTTPS probes | none | none | — |
| Speed testing | none | none | — |
| Interface counters and link state | none | none | traffic monitoring and bandwidth anomalies unavailable |
| Routing table and default gateway | none | none | gateway diagnostics and route-change detection unavailable |
| Active connection table | none | LocalSystem for other users' sockets | connection, destination and lateral analysis unavailable |
| Process attribution for connections | `CAP_DAC_READ_SEARCH` or root | Administrator | connections recorded without a process name or path |
| ICMP latency and packet loss | `CAP_NET_RAW`, or a `ping_group_range` covering the service group | Administrator | falls back to TCP connect timing; loss inferred from failed handshakes |
| Path measurement (traceroute) | `CAP_NET_RAW`, or an unprivileged ping socket | Administrator (raw socket) | path monitoring disabled |
| Wireless telemetry (SSID, RSSI, rate) | none | the WLAN AutoConfig service | Wi-Fi degradation cannot be distinguished from ISP problems |
| System resolver discovery | none | none | the configured `dns.fallback_servers` are used |
| Windows Event Log source | — | Administrator, at install time | events still reach the log files and the database |

### The Linux position

The service runs as the unprivileged `ipulse` account with exactly two capabilities:

```ini
AmbientCapabilities=CAP_NET_RAW CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_RAW CAP_DAC_READ_SEARCH
```

`CAP_NET_RAW` covers ICMP echo and TTL-limited path measurement. `CAP_DAC_READ_SEARCH`
covers reading `/proc/<pid>/fd` to map a socket inode to the process that owns it.

Both are optional. Removing them leaves a fully functional monitor with two documented
gaps, and iPulse reports each gap once at start-up as `IPULSE-8014 PRIVILEGE_LIMITED`
rather than failing silently:

```bash
sudo systemctl edit ipulse
```

```ini
[Service]
AmbientCapabilities=
CapabilityBoundingSet=
```

On many distributions ICMP works with no capability at all, because
`net.ipv4.ping_group_range` already includes ordinary groups. iPulse prefers the
unprivileged datagram ping socket and only falls back to a raw socket if it must.

### The Windows position

The Windows service runs as LocalSystem. Three functions require it: the extended socket
tables with process attribution, the WLAN API, and raw-socket ICMP. This is a real
privilege increase over the Linux configuration, so the exposure is bounded elsewhere —
the API is loopback-only, no remote input is accepted, and nothing iPulse reads is ever
executed.

## Hardening

### The systemd unit

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=/var/lib/ipulse /var/log/ipulse
MemoryMax=256M
TasksMax=64
```

The filesystem is read-only apart from the two directories iPulse owns. The only address
families available are the ones it uses. Memory and task count are capped so a bug cannot
starve the host it is monitoring.

### File permissions

| Path | Mode | Owner |
|---|---|---|
| `/etc/ipulse` | `0750` | `root:ipulse` |
| `/etc/ipulse/ipulse.yaml` | `0640` | `root:ipulse` |
| `/var/lib/ipulse` | `0750` | `ipulse:ipulse` |
| `/var/lib/ipulse/ipulse.db` | `0640` | `ipulse:ipulse` |
| `/var/log/ipulse` | `0750` | `ipulse:ipulse` |
| `/var/log/ipulse/*.log` | `0640` | `ipulse:ipulse` |

These are re-applied at every start rather than trusted to whatever the installer left
behind, and `security.AuditPaths` reports anything world-writable as a warning at
start-up. The database and logs contain connection metadata, so they are deliberately not
world-readable. Configuration validation rejects a `logging.file_mode` that grants group
or other write access, and warns about a world-readable one.

On Windows the installer replaces the inherited ProgramData ACL on the data and log
directories with SYSTEM and Administrators only.

### The API and dashboard

* **Loopback by default.** `dashboard.address` defaults to `127.0.0.1`. Binding anywhere
  else without `dashboard.auth_token` is a configuration error, not a warning.
* **Host allow-list.** Every request's `Host` header must be in
  `dashboard.allowed_hosts`. This is what makes a loopback-bound API safe against DNS
  rebinding: a page on the public Internet can resolve a name to 127.0.0.1, but it cannot
  make the browser send a Host header from the list.
* **No CORS.** No `Access-Control-Allow-Origin` header is ever emitted, so another origin
  cannot read API responses even if it reaches the port.
* **Optional bearer token,** compared in constant time, accepted as `X-iPulse-Token` or
  `Authorization: Bearer`. Minimum length 16 characters, enforced by validation.
* **Content-Security-Policy** of `default-src 'none'` with `'self'` for scripts, styles
  and connections. The dashboard uses no inline script or style and no external origin,
  so the policy needs no exceptions.
* **Rate limiting** on the endpoints that start real network activity, and those
  endpoints refuse non-loopback clients unless `dashboard.allow_remote_tests` is set.
* **Request bodies capped** at 64 KB; read, write and header timeouts on every request.
* **Secrets redacted** from `GET /api/v1/config`.

### Input handling

* **Configuration** is validated in full before it is applied, and unknown keys are
  rejected rather than ignored: a typo in a threshold must not be silently dropped. An
  invalid file leaves the previous configuration in force.
* **Log values are sanitised.** Process names, executable paths, SSIDs, reverse DNS
  answers, threat-feed comments and HTTP responses are all attacker-influenced. Every
  value has control characters and newlines escaped before it reaches a log line, so a
  process named `evil\n2026-01-01T00:00:00Z INFO IPULSE-1002 …` cannot forge a record.
  Quoting is applied when rendering text, so the stored and JSON forms keep the real value.
* **SQL** is exclusively parameterised. The only dynamic SQL is a fixed set of column and
  table names chosen by the code, never by input. `LIKE` wildcards in a user's search term
  are escaped so a search for `%` does not match everything.
* **No shell.** iPulse never invokes a shell. The single external command in the whole
  tree is `systemctl` for service management, called with a fixed argument list through
  `exec.Command` (no shell interpretation), and only from administrative commands.
* **Threat feeds are data.** Imported indicators are classified and validated; anything
  that is not a valid address, prefix or plausible domain is counted as unusable and
  discarded. Feed size and indicator count are bounded.
* **Path traversal** is not reachable: the dashboard is served from an embedded
  filesystem, so there is no filesystem path to traverse.

## Threat model

**What iPulse defends against**

* A hostile process on the monitored host trying to hide its network activity from the
  log, or to forge log records through its own name or command line.
* A web page in the user's browser trying to reach the local API (DNS rebinding, CORS,
  clickjacking).
* A malicious or compromised threat-intelligence feed trying to inject content or exhaust
  memory.
* A malicious speed-test or public-IP endpoint returning hostile or oversized responses.

**What iPulse does not defend against**

* An attacker who is already root or SYSTEM on the monitored host. They can stop the
  service, alter its configuration and edit its database. Ship logs elsewhere if that is
  in scope.
* Network-level tampering with measurement traffic. iPulse verifies TLS but a
  man-in-the-middle can still degrade or delay probes; that is what the measurements are
  for.
* An operator who deliberately exposes the dashboard to a hostile network with a weak
  token.

## Reducing exposure further

```yaml
connections:
  resolve_process: false        # do not attribute connections to processes
privacy:
  collect_process_names: false
  collect_executable_paths: false
  collect_usernames: false
  collect_remote_hostnames: false   # no reverse DNS
  anonymize_local_addresses: true   # mask the host portion of local addresses
dashboard:
  enabled: false                # API and dashboard off entirely; the CLI still works
threat_intel:
  enabled: false
routing:
  enabled: false                # no path measurement traffic
```

Each of these narrows what is recorded or emitted. The CLI reads the database directly,
so turning the dashboard off does not blind you.

## Reporting a vulnerability

Open an issue describing the impact and how to reproduce it. Please do not include
credentials, real IP addresses or captured data.
