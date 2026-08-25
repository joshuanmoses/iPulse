# The detection engine

Every detection in iPulse is a deterministic rule over stored numbers. There is no model,
no learning in the machine-learning sense, and no hidden score. Given the same sequence
of measurements, iPulse produces the same events — which is what makes the behaviour
reviewable, testable and arguable.

This document describes every rule, in the order the pipeline applies them.

```text
  measurement ──▶ baseline (time-aware) ──▶ deviation rule ──▶ gate ──▶ event
                                                                 │
                                     correlation window ◀────────┘
                                                 │
                                                 ▼
                                          one conclusion
```

## 1. Baselining

### What a baseline is keyed by

`(metric, dimension, time bucket)`. The dimension is an interface, probe target, resolver
or process — empty for connection-level metrics. The time bucket is
`{weekday|weekend}-{hour group}`, for example `wd-14` for a weekday 2 PM.

Time bucketing exists because comparing 2 PM on a Tuesday with 3 AM on a Sunday produces
nonsense. A backup that runs every night at 02:00 makes overnight traffic normal *at
02:00* and remains notable at 14:00.

### What a baseline holds

| Value | How it is computed | Why |
|---|---|---|
| count, mean, M2 | Welford's method | exact mean and variance without storing samples |
| min, max | running | range |
| EWMA (α = 0.1 default) | exponential | follows a genuine change in conditions |
| median, MAD | from a bounded recent-sample window | robust against outliers |
| p10, p25, p75, p90, p95, p99 | from the same window | distribution shape |

The recent-sample window is a sliding buffer (256 samples by default), not a random
reservoir, so the robust statistics describe recent behaviour rather than all of history.

### When a baseline may be used

Never before `baseline.min_observations` samples (default 30) exist for that key. This is
the single most important false-positive guard in iPulse: it is why a fresh installation
does not spend its first hour declaring everything anomalous.

When a specific time bucket is not yet established, detectors fall back to an aggregate
across all buckets for that metric, so detection works from the first hours without
waiting for all 48 buckets to fill. The event states which bucket was used and how many
observations back it.

### Comparing against history, not against itself

`Observe` returns the baseline **as it was before** the sample was folded in. A detector
that compared a value with a baseline the value had already moved would be blind to
exactly the changes it exists to catch.

### Persistence

Baselines are written to the database and restored at start-up, so a restart does not
reopen the false-positive window. `min_observations` is re-applied on load, so raising it
in configuration takes effect immediately. Buckets untouched for `baseline.max_sample_age`
are pruned, so a laptop that changes networks does not carry stale baselines forever.

## 2. The gate: persistence, cooldown, hysteresis

Every detector's output passes through a gate before it becomes an event.

| Control | Default | Effect |
|---|---|---|
| `alerts.persistence` | 2 | consecutive breaches required before firing |
| `alerts.cooldown` | 15m | minimum time before the same condition fires again |
| `alerts.recovery_persistence` | 3 | consecutive clears required before recovery is reported |

Without persistence, one bad probe on a busy Wi-Fi link produces an event. Without a
cooldown, a condition that lasts an hour produces an event every cycle. Without recovery
persistence, a value hovering at the threshold produces an endless alternation of
degraded and recovered.

Raising `persistence` trades detection latency for fewer false positives. It is the first
knob to reach for if iPulse is noisy on your network.

## 3. Deviation rules

### Relative deviation (quality metrics)

```text
deviation% = (current − reference) / reference × 100
fires when deviation ≥ threshold AND |current| ≥ minimum absolute
```

The reference is the median for metrics with occasional large outliers, which is most of
them.

| Metric | Direction | Threshold | Absolute floor | Event |
|---|---|---|---|---|
| `latency_ms` | above | `alerts.latency_degradation_percent` (100) | `alerts.min_absolute_latency_ms` (30 ms) | `LATENCY_DEGRADATION` |
| `jitter_ms` | above | `alerts.jitter_degradation_percent` (150) | 2 ms | `JITTER_DEGRADATION` |
| `dns_ms` | above | `alerts.dns_degradation_percent` (200) | 50 ms | `DNS_RESPONSE_DEGRADATION` |
| `download_mbps` | below | `alerts.download_degradation_percent` (40) | `alerts.min_absolute_mbps` (5) | `DOWNLOAD_DEGRADATION` |
| `upload_mbps` | below | `alerts.upload_degradation_percent` (40) | `alerts.min_absolute_mbps` | `UPLOAD_DEGRADATION` |
| `light_download_mbps` | below | `alerts.download_degradation_percent` | `alerts.min_absolute_mbps` | `THROUGHPUT_DEGRADATION` |
| `wifi_link_mbps` | below | `wifi.link_speed_degrade_percent` (50) | 1 Mbps | `WIFI_LINK_SPEED_DEGRADED` |

**The absolute floor matters.** A 5 ms baseline rising to 12 ms is a 140 % deviation and
is not a problem. Without the floor, iPulse would be loudest on the best connections.

### Robust deviation (traffic and counts)

```text
z = (value − median) / (1.4826 × MAD)
fires when z ≥ threshold AND value ≥ absolute floor
```

Median and MAD rather than mean and standard deviation, because traffic distributions are
heavily skewed: a handful of large transfers inflates a conventional standard deviation
until nothing can ever exceed it. When MAD is zero — a perfectly steady metric, common on
an idle link — the score falls back to relative deviation rather than dividing by zero.

| Metric | Threshold | Floor | Event |
|---|---|---|---|
| `rx_bps` | `traffic.spike_z_score` (6) | `traffic.spike_min_mbps` (5 Mbps) | `BANDWIDTH_SPIKE_DOWNLOAD` |
| `tx_bps` | `traffic.spike_z_score` | `traffic.spike_min_mbps` | `BANDWIDTH_SPIKE_UPLOAD` |
| `connection_count` | `traffic.spike_z_score` | 10 | `CONNECTION_COUNT_ANOMALY` |
| `tx_bytes_window` | `traffic.spike_z_score` | `destinations.high_volume_mb` | `UNUSUAL_OUTBOUND_TRAFFIC` |
| `rx_bytes_window` | `traffic.spike_z_score` | `destinations.high_volume_mb` | (quiet hours only) |

The absolute floor prevents the opposite failure: on an idle link, 1 Mbps is a
thousandfold increase and still not worth an event.

### Sustained conditions

Rate answers "how fast now"; duration answers "for how long". A large file transfer and
an hour of steady uploading look identical for one sample and are entirely different
events.

| Condition | Floor | Duration | Event |
|---|---|---|---|
| upload above floor | `traffic.sustained_upload_mbps` (2) | `alerts.sustained_upload_seconds` (120) | `SUSTAINED_UPLOAD` |
| either direction above floor | `traffic.spike_min_mbps` | `traffic.sustained_seconds` (300) | `SUSTAINED_BANDWIDTH_USAGE` |

### Volume windows

A transfer can start and finish between two rate samples. iPulse therefore accumulates
transferred bytes over a rolling five-minute window and baselines *that* as well, which is
what catches an upload that a rate sample would miss. The window must be full before it is
compared, so a partial window is never read as a drop in volume.

### Quiet hours

Between `traffic.quiet_hours_start` and `traffic.quiet_hours_end` (01:00–06:00 by
default), a volume anomaly is reported as `UNUSUAL_OVERNIGHT_ACTIVITY` rather than as a
plain outbound-traffic event. The time bucketing already accounts for the difference
statistically; the separate event exists because "at 3 AM" is the part an operator reads
first.

### Periodic patterns

Spike timestamps are retained per direction. When at least four intervals have a
coefficient of variation below 0.2, iPulse reports `PERIODIC_SPIKE_PATTERN` with the
period. Regular spikes are usually scheduled work, so this is context rather than an
alarm — and once recognised, the pattern explains the individual spikes.

### Absolute-threshold rules

Two rules need no history at all:

* **Packet loss** above `alerts.packet_loss_percent` (2 %), with persistence. Total loss
  is deliberately *not* reported as a loss event: that is an outage, handled below.
* **Slow DNS** above `dns.slow_threshold` (250 ms), with persistence.

## 4. Outage diagnosis

A failed health check escalates to a layered ladder. Every layer is tested even when a
lower one has already failed, because the full picture is what makes the outage record
useful afterwards.

```text
local device → network interface → default gateway → DNS → ISP → Internet
```

| Layer | Test |
|---|---|
| local device | a loopback listener accepts a connection |
| interface | link up, carrier present, a routable address assigned |
| gateway | default route present; gateway answers ICMP, or TCP on 80/443/53, or resets |
| DNS | resolution against the configured resolvers, then against the public fallbacks |
| ISP | TCP/443 to several IP literals in different networks — no DNS involved |
| Internet | full HTTPS sessions to several independent endpoints |

`Classify(evidence)` is a pure function, so a classification can be reproduced from the
stored evidence with no network. The rules, in order — the lowest broken layer wins,
because a failure there explains everything above it:

| Evidence | Conclusion |
|---|---|
| interface down, or no routable address | `LOCAL_INTERFACE_FAILURE` |
| wireless up but not associated, gateway unreachable | `LOCAL_INTERFACE_FAILURE` |
| no default route | `ROUTING_FAILURE` |
| gateway unreachable **and** nothing beyond it reachable | `GATEWAY_FAILURE` |
| gateway fine, DNS fails, IP literals reachable | `DNS_FAILURE` |
| gateway fine, DNS fine, no external target reachable | `ISP_OUTAGE` |
| some external targets reachable, others not | `PARTIAL_CONNECTIVITY` |
| no HTTPS session completes, all with TLS errors, TCP works | `CAPTIVE_PORTAL` |
| weak Wi-Fi with total external loss | `WIFI_DEGRADATION` |
| everything reachable | `HEALTHY` |

Two deliberate refusals:

* **An unresponsive gateway with a working Internet is not a fault.** Many routers answer
  nothing. Gateway failure is only concluded when nothing beyond it works either.
* **A failed cheap check with a healthy full ladder is not an outage.** It means one probe
  target is unavailable, and is reported as `PARTIAL_CONNECTIVITY` with no outage record.

### Outage lifecycle

`connectivity.failures_before_outage` consecutive failures (default 2) open an outage;
`connectivity.successes_before_recovery` consecutive successes (default 2) close it. A
flapping link therefore produces no outage record at all. An outage that was open when the
agent restarts is adopted rather than duplicated.

## 5. Correlation

Correlation replaces a list of symptoms with one conclusion. Each rule names its
conditions, and the emitted event carries the evidence that satisfied them, so the
conclusion can be checked rather than trusted. Rules are evaluated most-specific first and
at most one fires per evaluation.

The engine never ingests its own conclusions, so it cannot feed on itself.

### local-bandwidth-saturation → `LOCAL_BANDWIDTH_SATURATION`

| Requires |
|---|
| a bandwidth spike or sustained usage event |
| a latency degradation event |
| packet loss, a throughput drop, or measured loss ≥ 1 % |

This is the most common misdiagnosis in home and small-office networks: something local
is using the link, and the Internet gets blamed. The event names the direction and the
process most active at the time.

### wifi-degradation → `WIFI_DEGRADATION`

| Requires |
|---|
| a weak-signal or degraded-link-rate event |
| a latency, jitter or loss event |
| the local hop is affected (gateway RTT ≥ 15 ms, or unmeasurable) |

The third condition is the discriminating one. Weak signal with a *fast* gateway means the
loss is upstream, and the rule declines rather than blaming the radio.

### dns-slowness → `DNS_RESPONSE_DEGRADATION`

| Requires |
|---|
| a slow-DNS or partial-DNS-failure event |
| no outage and no latency degradation in the window |

Users experience slow DNS as "the Internet is slow". The fix is a resolver change, not an
ISP call — but only when the path itself is healthy, so the rule declines during an outage.

### vpn-routing-change → `VPN_ROUTING_CHANGE`

| Requires |
|---|
| a tunnel-state, default-interface or gateway change |
| a public IP, ASN or resolver change alongside it |

One VPN connection produces four separate notices. This groups them into one explanation
and suppresses the rest.

### isp-performance-degradation → `UPSTREAM_PERFORMANCE_DEGRADATION`

| Requires |
|---|
| throughput below baseline or below the configured plan |
| no local saturation |
| no wireless degradation |

This is the evidence an ISP ticket needs: the link was idle and the radio was healthy
while throughput was low.

### Suppression

With `correlation.suppress_contributing` (default true), contributing events are marked
as absorbed in the database, so the dashboard, the API and `ipulse events` show the
conclusion rather than the symptoms. The append-only log files keep every raw record, so
an operator tailing a file still sees everything as it happens. `ipulse events
--suppressed` shows them.

## 6. Destination analysis

| Finding | Condition | Confidence |
|---|---|---|
| `NEW_EXTERNAL_DESTINATION` | first contact with an address/port/protocol | low |
| `NEW_HIGH_VOLUME_DESTINATION` | new within `new_destination_window` **and** ≥ `high_volume_mb` sent | medium |
| `RARE_DESTINATION_CONTACT` | contact count below the `rare_percentile` of all destinations | low |
| `UNEXPECTED_DESTINATION_PORT` | port outside the configured set and seen fewer than 5 times | low |
| `RAPID_DESTINATION_FANOUT` | ≥ `fanout_threshold` distinct destinations in `fanout_window`, per process | low |

Novelty on its own is unremarkable — a CDN node, an update server, a newly resolved
address — so it is informational. Novelty *plus volume* is the combination worth
attention.

Nothing at all is reported during `destinations.learning_period` (2 hours by default),
because everything is new on the first day and the log would be useless.

The port profile is learned, not fixed: a port becomes normal for this host after five
observations, so a site's own application stops being reported.

## 7. Lateral movement

Per process, in a sliding window (`lateral.window`, 2 minutes):

| Finding | Condition |
|---|---|
| `INTERNAL_HOST_SWEEP` | ≥ `host_sweep_threshold` distinct internal hosts (20) |
| `POSSIBLE_PORT_SCAN` | ≥ `port_scan_threshold` distinct ports on one host (15) |
| `REMOTE_ADMIN_PROTOCOL_SWEEP` | ≥ `admin_sweep_hosts` hosts on admin ports (5) **and** failures present, or twice the threshold |
| `REPEATED_INTERNAL_CONNECTION_FAILURES` | ≥ `failed_connection_threshold` failed attempts (25) |

Confidence grading, in which failure rate carries the most weight because it is what
separates probing from use:

| Signal | Points |
|---|---|
| every attempt failed | 3 |
| more than half failed | 2 |
| any failures | 1 |
| three times the threshold | 2 |
| twice the threshold | 1 |
| sequential addresses or ports | 1 |

4 or more is high, 2–3 medium, otherwise low.

**The language is deliberate.** Every finding says "possible", names the benign
explanations, and never asserts compromise. The same pattern is produced by a
vulnerability scanner, a backup agent enumerating shares, a monitoring system and an
attacker; the event gives an operator what they need to tell them apart in seconds — the
process, the executable path, the user, the hosts, the ports and the failure rate.

`lateral.allow_processes` silences approved scanners, which most sites have. Without it,
those events would train operators to ignore the whole category.

## 8. Threat intelligence

Indicators are matched by exact address, containing CIDR, or domain including parent
domains. Private addresses are skipped unless `threat_intel.match_private` is set, and
`threat_intel.allow_list` covers your own infrastructure appearing in a public feed.

| Match | Event |
|---|---|
| high-confidence indicator | `KNOWN_MALICIOUS_DESTINATION` (error) |
| any other confidence | `THREAT_INTELLIGENCE_MATCH` (warning) |
| domain indicator | `MALICIOUS_DOMAIN_CONNECTION` (warning) |

Every match records the indicator, its source feed, its confidence and when that feed was
last updated — because a match is only as good as the feed behind it, and feeds carry
false positives. iPulse does not block traffic.

## 9. The health score

```text
score = Σ(weightᵢ × componentᵢ) / Σ(weightᵢ)
```

Each component is scaled 0–100 by linear interpolation between a good and a bad threshold
from the configuration. Components with no measurement are **excluded** and their weight
redistributed, rather than counted as zero — otherwise a fresh installation would report a
terrible score before its first speed test.

| Component | Default weight | 100 at | 0 at |
|---|---|---|---|
| availability | 30 | 100 % | 0 % |
| latency | 20 | `health.latency_good_ms` (20) | `health.latency_bad_ms` (200) |
| packet loss | 12 | `health.loss_good_percent` (0) | `health.loss_bad_percent` (5) |
| download | 15 | your plan | a tenth of your plan |
| upload | 10 | your plan | a tenth of your plan |
| jitter | 8 | `health.jitter_good_ms` (3) | `health.jitter_bad_ms` (50) |
| DNS | 5 | `health.dns_good_ms` (20) | `health.dns_bad_ms` (500) |

Throughput is only scored when an ISP plan is configured, because without one there is no
absolute reference for "fast enough".

Inputs are medians over `health.window` rather than the latest reading, except packet
loss, which uses the mean: a short burst of loss is a real quality problem that a median
would hide entirely.

`GET /api/v1/health` returns the score, every component, the effective weights and the
formula, so any number iPulse reports can be reproduced by hand.

## Tuning for a noisy network

1. Raise `alerts.persistence` from 2 to 3 or 4. Fewer events, slightly later.
2. Raise `baseline.min_observations` from 30 to 60. Longer learning, steadier baselines.
3. Raise `traffic.spike_z_score` from 6 to 8, or `traffic.spike_min_mbps` to a rate that
   actually matters on your link.
4. Raise `alerts.min_absolute_latency_ms` if your baseline latency is very low.
5. Lengthen `alerts.cooldown` if a genuine long-lived condition is repeating too often.
6. Add approved scanners to `lateral.allow_processes` and your own networks to
   `threat_intel.allow_list` and `lateral.extra_private_ranges`.

Every threshold is in one file, and `ipulse config validate` checks them before they take
effect.
