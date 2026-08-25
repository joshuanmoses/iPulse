# Configuration

| Platform | Path |
|---|---|
| Linux | `/etc/ipulse/ipulse.yaml` |
| Windows | `C:\ProgramData\iPulse\config\ipulse.yaml` |
| Portable | `<portable root>/config/ipulse.yaml` |

Override with `--config <path>` or the `IPULSE_CONFIG` environment variable.

Every key is optional: anything omitted falls back to the documented default. **Unknown
keys are rejected**, because a silently-ignored typo in a threshold is worse than a
refusal to start.

```bash
ipulse config              # the effective configuration, secrets redacted
ipulse config validate     # check a file, reporting every problem at once
ipulse config default      # the built-in defaults
ipulse config path         # where everything lives
ipulse config init         # write a default file if none exists
```

Durations are written with units (`15s`, `5m`, `30m`, `24h`). A bare number is rejected
rather than being interpreted as nanoseconds.

## Applying changes

```bash
sudo systemctl reload ipulse      # Linux
Restart-Service iPulse            # Windows
```

Applied on reload: alert thresholds, baseline settings, correlation, health weights, ISP
expectations, traffic thresholds, destination and lateral settings, threat intelligence,
and the log level.

Needs a restart: `dashboard.address`, `dashboard.port`, `database.path`,
`service.log_dir`, and the `monitoring` intervals. The reload event lists which of those
changed.

An invalid file is rejected and the previous configuration stays in force.

---

## service

```yaml
service:
  data_dir: ""              # default: /var/lib/ipulse or C:\ProgramData\iPulse\data
  log_dir: ""               # default: /var/log/ipulse or C:\ProgramData\iPulse\logs
  hostname_override: ""     # replaces the detected hostname in records
  shutdown_timeout: 20s     # bound on graceful shutdown
  startup_grace: 45s        # delay before the first full speed test
```

`startup_grace` keeps a boot-time speed test from competing with everything else starting
up, and from measuring a link that is still settling.

## monitoring

Every interval is configurable. The defaults are chosen so steady-state cost is a few
TCP handshakes and DNS queries per minute.

```yaml
monitoring:
  health_interval: 15s                # reachability check
  dns_interval: 30s                   # one name per cycle, round-robin
  latency_interval: 30s               # ICMP or TCP timing
  interface_interval: 30s             # interface, route and resolver state
  wifi_interval: 60s                  # wireless telemetry
  public_ip_interval: 5m
  route_interval: 30m                 # path measurement
  traffic_interval: 5s                # interface counters
  connection_interval: 15s            # socket table
  health_score_interval: 1m
  baseline_flush_interval: 5m         # persist learned baselines
  retention_interval: 6h              # prune old rows
  availability_report_interval: 24h
  threat_feed_interval: 12h
  probe_timeout: 5s                   # bound on any single probe
  jitter: 2s                          # spread so tasks do not fire together
```

Minimums are enforced by validation. `probe_timeout` should stay shorter than
`health_interval`, or checks overlap and get skipped — validation warns if it does not.

## connectivity

```yaml
connectivity:
  targets:                            # cheap, frequent reachability checks
    - {name: cloudflare-dns, type: tcp, address: "1.1.1.1:443", notes: AS13335}
    - {name: google-dns,     type: tcp, address: "8.8.8.8:443", notes: AS15169}
    - {name: quad9-dns,      type: tcp, address: "9.9.9.9:443", notes: AS19281}
  required_success: 1                 # how many must answer for the link to be up
  ip_literals: [1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222]
  https_targets:
    - https://www.cloudflare.com/cdn-cgi/trace
    - https://connectivitycheck.gstatic.com/generate_204
    - https://checkip.amazonaws.com
  failures_before_outage: 2
  successes_before_recovery: 2
  gateway_probe_method: auto          # auto | icmp | tcp
  gateway_tcp_ports: [80, 443, 53]
```

Target `type` is `tcp`, `https` or `icmp`.

**Keep the targets in different networks.** Diversity is what lets iPulse tell "one
provider is down" from "our Internet is down". Three targets in the same ASN cannot make
that distinction.

`ip_literals` are probed without DNS, which is how a name-resolution failure is separated
from a path failure. `https_targets` verify a complete TLS session, which is what catches
a captive portal that answers TCP.

Note that `www.msftconnecttest.com` is intended for plain-HTTP captive-portal detection
and does not present a matching certificate; it is deliberately not in the default HTTPS
list.

## dns

```yaml
dns:
  names: [www.google.com, cloudflare.com, wikipedia.org, github.com]
  servers: []                         # empty: use the system resolvers
  fallback_servers: ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]
  timeout: 3s
  slow_threshold: 250ms
  use_system_resolver: true
```

One name is resolved per cycle, round-robin: resolving all four every cycle would
quadruple the query load for no extra information.

`fallback_servers` are only queried during diagnosis, and only to answer one question:
is the local resolver broken, or is the network?

## latency

```yaml
latency:
  targets: [1.1.1.1, 8.8.8.8]
  probes: 5                           # per target per cycle; loss is derived from this
  spacing: 200ms
  timeout: 2s
  method: auto                        # auto | icmp | tcp
  tcp_port: 443
  include_gateway: true
```

`auto` prefers ICMP and falls back to TCP connect timing where ICMP is not permitted, and
records which was used with every result. A target that never answers ICMP is remembered
for 15 minutes so it is not probed twice every cycle.

`include_gateway` is what separates local-network latency from Internet latency, and it
is what several correlation rules depend on. Leave it on.

Fewer than four probes makes the loss percentage very coarse; validation warns.

## speed_test

```yaml
speed_test:
  enabled: true
  provider: http
  lightweight_interval: 5m
  full_interval: 30m

  expected_download_mbps: 0           # ← set these to your plan
  expected_upload_mbps: 0

  streams: 4
  warmup: 2s                          # discarded, so slow-start does not depress the result
  duration: 10s
  upload_duration: 8s
  max_download_bytes: 536870912       # 512 MiB hard cap
  max_upload_bytes: 134217728         # 128 MiB hard cap
  lightweight_bytes: 2097152
  skip_if_busy_mbps: 10               # skip when the link is already this busy (0 disables)
  endpoint_selection: latency         # latency | first | random
  upload_enabled: true
  timeout: 90s

  endpoints:
    - name: cloudflare
      download_url: https://speed.cloudflare.com/__down?bytes={bytes}
      upload_url: https://speed.cloudflare.com/__up
      latency_url: https://speed.cloudflare.com/__down?bytes=1000
      max_streams: 8
      location: anycast
      enabled: true
```

**Set your plan.** Without `expected_*_mbps`, iPulse can tell you the number but not
whether it is good. With it, you get shortfall reporting, throughput in the health score
and an evidence trail for an ISP conversation.

**On a metered connection**, lower the caps and lengthen the intervals:

```yaml
speed_test:
  full_interval: 6h
  max_download_bytes: 52428800     # 50 MiB
  max_upload_bytes: 10485760       # 10 MiB
  upload_enabled: false
```

Roughly: `full_interval: 30m` with the default caps transfers up to about 30 GB a day on a
very fast link, and far less on a slower one, because the time bound usually ends the test
first. The byte cap is enforced the moment it is reached, not at the next sampling
boundary.

**Any HTTP server works.** An endpoint needs to serve a sized body and accept a POST. To
measure against your own infrastructure:

```yaml
    - name: internal
      download_url: https://speedtest.example.internal/download?bytes={bytes}
      upload_url: https://speedtest.example.internal/upload
      max_streams: 8
```

The `{bytes}` placeholder is replaced with the per-request chunk size. Endpoints without
it are requested repeatedly instead, which works for a static file.

## traffic

```yaml
traffic:
  enabled: true
  interfaces: []                      # empty: every non-loopback interface
  exclude_interfaces: ["lo", "lo*", "docker*", "br-*", "veth*", "virbr*", "Loopback*"]
  spike_z_score: 6                    # robust z-score for a spike
  spike_min_mbps: 5                   # absolute floor, so an idle link stays quiet
  sustained_seconds: 300
  sustained_upload_mbps: 2
  large_transfer_mb: 512
  quiet_hours_start: 1                # local time, 24h clock
  quiet_hours_end: 6
  exclude_self_traffic: true          # attribute iPulse's own tests to iPulse
  error_rate_threshold: 5             # errors+drops per second
```

Leave `exclude_self_traffic` on. It is what stops every speed test from raising a
bandwidth anomaly about itself.

Virtual interfaces are excluded because they double-count what the real interface already
reported.

## connections

```yaml
connections:
  enabled: true
  include_udp: true
  include_listening: false
  include_loopback: false
  resolve_process: true
  max_connections_per_sample: 4096
  idle_timeout: 5m
```

`resolve_process` needs `CAP_DAC_READ_SEARCH` on Linux or Administrator on Windows to see
other users' sockets. Without it, connections are still recorded, without a process name.

## destinations

```yaml
destinations:
  enabled: true
  new_destination_window: 24h
  learning_period: 2h                 # nothing is reported until the normal picture exists
  rare_percentile: 5
  high_volume_mb: 64
  fanout_window: 1m
  fanout_threshold: 60
  expected_ports: [53, 80, 123, 443, 465, 587, 853, 993, 995, 5223, 8443]
  reverse_dns: true
  enrichment: []                      # empty: no external service is contacted
  enrichment_url: ""                  # optional, with an {ip} placeholder
  ignore_destinations: []             # addresses or CIDRs never reported
  ignore_processes: []                # process names (globs) never recorded
```

The port profile is learned as well as configured: a port becomes normal for this host
after five observations, so your own applications stop being reported.

## threat_intel

```yaml
threat_intel:
  enabled: true
  feeds: []                           # none by default: iPulse contacts nobody
  max_indicators: 2000000
  expire_after: 720h                  # drop indicators a feed stopped publishing
  match_private: false
  allow_list: []                      # your own infrastructure
```

```yaml
  feeds:
    - name: local-iocs
      type: ioc                       # ip | cidr | domain | ioc
      format: auto                    # plain | hosts | csv | json | auto
      path: /etc/ipulse/threat/iocs.txt
      confidence: medium              # low | medium | high
    - name: example-blocklist
      type: ip
      format: plain
      url: https://example.org/blocklist.txt
      confidence: high
    - name: csv-feed
      type: ip
      format: csv
      column: 2                       # 1-based
      path: /var/lib/threat/export.csv
    - name: json-feed
      type: domain
      format: json
      field: attributes.value         # dot path
      url: https://example.org/iocs.json
```

Only `high` confidence produces `KNOWN_MALICIOUS_DESTINATION`; anything else is reported
as `THREAT_INTELLIGENCE_MATCH`. Conditional requests (ETag) avoid re-downloading an
unchanged feed.

## lateral

```yaml
lateral:
  enabled: true
  window: 2m
  host_sweep_threshold: 20
  port_scan_threshold: 15
  failed_connection_threshold: 25
  admin_ports: [22, 135, 139, 445, 3389, 5900, 5985, 5986]
  admin_sweep_hosts: 5
  allow_processes: []                 # approved scanners and management tools
  extra_private_ranges: []            # site networks that are technically public
```

If you run a vulnerability scanner, put it in `allow_processes`. Otherwise it will be
reported daily and people will learn to ignore the category.

## public_ip

```yaml
public_ip:
  enabled: true
  providers: [https://1.1.1.1/cdn-cgi/trace, https://api.ipify.org, https://icanhazip.com]
  ipv6_providers: [https://api6.ipify.org, https://ipv6.icanhazip.com]
  timeout: 6s
  confirm_changes: true               # two providers must agree before recording a change
  asn_lookup: true
  asn_provider_url: ""                # empty: DNS-based Team Cymru, no key, no HTTP
```

## routing

```yaml
routing:
  enabled: true
  destinations: [1.1.1.1, 8.8.8.8]
  max_hops: 20
  probes_per_hop: 1
  timeout: 20s
  hop_change_tolerance: 1             # ECMP causes benign hop variation
```

One destination is measured per cycle, round-robin. Path measurement is the most visible
traffic iPulse generates; set `enabled: false` if that matters on your network.

## wifi

```yaml
wifi:
  enabled: true
  weak_signal_dbm: -70
  link_speed_degrade_percent: 50
```

Roughly: −50 dBm is excellent, −60 good, −70 usable, −80 poor.

## baseline

```yaml
baseline:
  min_observations: 30                # the primary false-positive guard
  window: 336h                        # 14 days
  time_buckets: true                  # compare 2 PM with other 2 PMs
  bucket_hours: 1                     # 1, 2, 3, 4, 6, 8, 12 or 24
  ewma_alpha: 0.1
  reservoir_size: 256                 # recent samples kept for percentiles
  max_sample_age: 720h
```

Raise `min_observations` if detection is noisy; lower it (not below 10) if you want faster
learning on a stable network.

## alerts

```yaml
alerts:
  download_degradation_percent: 40
  upload_degradation_percent: 40
  latency_degradation_percent: 100
  jitter_degradation_percent: 150
  packet_loss_percent: 2
  dns_degradation_percent: 200
  isp_shortfall_percent: 30
  sustained_upload_seconds: 120
  sustained_latency_seconds: 120
  sustained_bandwidth_seconds: 300
  persistence: 2                      # consecutive breaches before an event
  recovery_persistence: 3
  cooldown: 15m
  min_absolute_latency_ms: 30         # ignore relative rises while the value is fine
  min_absolute_mbps: 5
```

The two absolute floors matter more than they look. Without `min_absolute_latency_ms`, a
5 ms baseline rising to 12 ms is a "140 % degradation", and iPulse would be loudest on the
best connections.

## correlation

```yaml
correlation:
  enabled: true
  window: 3m
  suppress_contributing: true
```

Suppression marks contributing events as absorbed in the database. The dashboard, the API
and `ipulse events` then show the conclusion; the log files keep every raw record.

## health

```yaml
health:
  enabled: true
  weights:
    availability: 30
    download: 15
    upload: 10
    latency: 20
    jitter: 8
    packet_loss: 12
    dns: 5
  window: 1h
  warn_below: 70
  latency_good_ms: 20
  latency_bad_ms: 200
  jitter_good_ms: 3
  jitter_bad_ms: 50
  loss_good_percent: 0
  loss_bad_percent: 5
  dns_good_ms: 20
  dns_bad_ms: 500
```

Weights are normalised, so they do not have to sum to 100. A component with no
measurement is excluded and its weight redistributed. Throughput is only scored when
`speed_test.expected_*_mbps` is set.

For a connection where latency matters more than throughput (VoIP, gaming), raise
`latency` and `jitter` and lower `download`.

## logging

```yaml
logging:
  level: info                         # debug | info | notice | warning | error | critical
  text: true                          # ipulse.log, human readable
  json: true                          # ipulse.jsonl, one object per line
  database: true                      # searchable events table
  syslog: true                        # journald on Linux
  eventlog: true                      # Windows Event Log
  console: false                      # stderr; automatic in foreground mode
  syslog_severity: notice             # minimum severity for the OS log
  max_file_mb: 100
  max_archives: 10
  retention_days: 30
  compress: true
  rotate_daily: false
  file_mode: "0640"
```

`syslog` and `eventlog` are both on by default so one configuration file works on both
platforms; the inapplicable one is skipped silently.

Routine measurements are logged at `debug` and are off by default: a health check every
15 seconds at `info` would be 5,760 records a day and would bury everything else. The
measurements are always stored in the database regardless of log level.

Validation rejects a `file_mode` granting group or other write access, and warns about a
world-readable one.

## database

```yaml
database:
  path: ""                            # default: <data_dir>/ipulse.db
  busy_timeout: 5s
  retention:
    events_days: 90
    measurements_days: 30
    speed_tests_days: 365
    outages_days: 365
    connections_days: 14
    destinations_days: 180
    traffic_days: 30
    aggregates_days: 730
  max_size_mb: 2048
  vacuum_interval: 24h
  downsample: true
```

With `downsample`, raw measurements are rolled into hourly aggregates before deletion, so
a year of charts survives on a fraction of the space. Unresolved outages are never
deleted, however old.

Rough sizing with the defaults: tens of megabytes for a quiet host over a month, a few
hundred for a busy one. `max_size_mb` produces a warning, not a deletion.

## dashboard

```yaml
dashboard:
  enabled: true
  address: 127.0.0.1
  port: 8750
  auth_token: ""
  allowed_hosts: ["127.0.0.1", "localhost", "[::1]"]
  allow_remote_tests: false
  read_timeout: 15s
  write_timeout: 60s
  rate_limit_per_minute: 10
  tls_cert_file: ""
  tls_key_file: ""
```

Binding to anything other than loopback **requires** `auth_token` and is rejected without
it. If you do expose it, add the address to `allowed_hosts`, set TLS, and put it behind a
firewall. See [security.md](security.md).

## privacy

```yaml
privacy:
  collect_process_names: true
  collect_executable_paths: true
  collect_usernames: true
  collect_remote_hostnames: true      # reverse DNS
  anonymize_local_addresses: false
  payload_inspection: false           # reserved; setting true is rejected
```

See [privacy.md](privacy.md).

---

## Worked examples

### Home connection, 500/50 plan

```yaml
speed_test:
  expected_download_mbps: 500
  expected_upload_mbps: 50
```

That single change is usually the whole configuration.

### Metered or mobile

```yaml
speed_test:
  full_interval: 12h
  lightweight_interval: 30m
  max_download_bytes: 26214400      # 25 MiB
  max_upload_bytes: 5242880         # 5 MiB
  upload_enabled: false
monitoring:
  health_interval: 60s
  latency_interval: 5m
routing:
  enabled: false
```

### Quiet, only real problems

```yaml
logging:
  level: notice
alerts:
  persistence: 4
  cooldown: 1h
baseline:
  min_observations: 60
traffic:
  spike_z_score: 8
destinations:
  enabled: false
```

### Server with a strict change-control regime

```yaml
lateral:
  allow_processes: [nessus-agent, qualys-cloud-agent, ansible-*]
  extra_private_ranges: ["100.100.0.0/16"]
threat_intel:
  allow_list: ["203.0.113.0/24", "mirror.example.internal"]
connections:
  include_listening: true
```

### Latency-sensitive (VoIP, gaming, trading)

```yaml
monitoring:
  latency_interval: 10s
latency:
  probes: 10
  spacing: 100ms
alerts:
  latency_degradation_percent: 50
  jitter_degradation_percent: 100
  packet_loss_percent: 0.5
  min_absolute_latency_ms: 15
health:
  weights: {availability: 25, latency: 30, jitter: 20, packet_loss: 20, dns: 5, download: 0, upload: 0}
```
