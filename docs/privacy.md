# Privacy

iPulse is a monitoring agent that runs continuously on a machine you own and watches its
network activity. That is inherently sensitive, so this document states exactly what it
records, what it never records, and how to record less.

## The short version

* iPulse collects **metadata only**: which process connected to which address on which
  port, when, for how long, and how the connection performed.
* It performs **no payload capture** and **no TLS interception**, in any configuration.
* **Nothing leaves the machine** except the measurement traffic you configure.
* There is **no cloud account, no telemetry, no analytics, no phone-home**.
* All data is stored locally and expires under a retention policy you control.

## What is recorded

**Connection quality.** Latency, jitter, packet loss, DNS response time, throughput,
TCP connect time, HTTPS time-to-first-byte, hop counts and per-hop latency. Numbers about
your connection, not about you.

**Network configuration.** Interface names, types, MAC addresses, IP addresses, MTU, link
speed, routing table, default gateway, configured resolvers, and Wi-Fi association
details: SSID, BSSID, signal strength, link rate, channel and band.

**Connections.** For each active TCP and UDP socket: protocol, local and remote address
and port, connection state, first and last seen, duration, and — where the platform
permits and the configuration allows — the owning process ID, process name, executable
path and account name.

**Destinations.** Per remote endpoint: first seen, last seen, contact count, associated
processes, and optionally reverse DNS and autonomous-system information.

**Public addresses.** Your public IPv4 and IPv6 addresses, their history, and the ASN and
organisation serving them.

**Events.** The record of everything iPulse decided, including the fields above where
they are relevant to the decision.

## What is never recorded

iPulse does not capture, store or transmit:

* packet payloads of any kind
* HTTP request or response bodies, headers, URLs or cookies
* TLS plaintext — there is no interception, no proxy and no certificate injection
* file contents, documents or clipboard data
* keystrokes, screen contents or user input
* passwords, tokens or credentials of any kind
* Wi-Fi passphrases or network profiles — the wireless collectors read association
  metadata only, and never touch the credential store
* email, message or chat content
* browsing history as such (a destination address is recorded; the page is not)

`privacy.payload_inspection` exists in the configuration schema for one reason: so that
setting it to `true` is **rejected** by validation with an explicit message. There is no
code path that inspects a payload.

## What leaves the machine

Only measurement traffic, and only to endpoints in your configuration:

| Traffic | Destinations | Purpose | Turn off with |
|---|---|---|---|
| TCP health checks | `connectivity.targets` | is the Internet reachable | (core function) |
| HTTPS probes | `connectivity.https_targets` | does a full TLS session complete | empty the list |
| DNS queries | your resolvers, plus `dns.fallback_servers` during diagnosis | name resolution timing | (core function) |
| ICMP echo | `latency.targets`, your gateway | latency and packet loss | `latency.method: tcp` |
| Speed tests | `speed_test.endpoints` | throughput | `speed_test.enabled: false` |
| Public IP lookup | `public_ip.providers` | your public address | `public_ip.enabled: false` |
| ASN lookup | Team Cymru over DNS, or your configured endpoint | who serves the address | `public_ip.asn_lookup: false` |
| Reverse DNS | your resolvers | destination names | `privacy.collect_remote_hostnames: false` |
| Path measurement | `routing.destinations` | hop-by-hop path | `routing.enabled: false` |
| Threat feeds | feeds you add — none by default | indicator import | `threat_intel.feeds: []` |

The requests carry no identifying information beyond what any HTTP client sends: the
`User-Agent` is `iPulse/1.0` and no cookies, tokens or identifiers are included. The ASN
lookup uses DNS rather than HTTP precisely because it reveals only the address being
looked up, and needs no account.

## Where data is stored

| Platform | Location |
|---|---|
| Linux | `/var/lib/ipulse/ipulse.db`, `/var/log/ipulse/` |
| Windows | `C:\ProgramData\iPulse\data\`, `C:\ProgramData\iPulse\logs\` |
| Portable | everything under the directory you name |

Permissions restrict these to the service account and administrators. See
[security.md](security.md).

## How long data is kept

Every table has its own retention, and pruning runs on a schedule:

```yaml
database:
  retention:
    events_days: 90
    measurements_days: 30
    speed_tests_days: 365
    outages_days: 365
    connections_days: 14         # connection records are the most identifying
    destinations_days: 180
    traffic_days: 30
    aggregates_days: 730
```

Raw measurements are rolled up into hourly aggregates before deletion, so long-range
charts survive without keeping the detail. Connection records default to the shortest
retention of anything in the database.

Log files rotate at `logging.max_file_mb` and archives are deleted after
`logging.retention_days`.

## Reducing what is collected

```yaml
privacy:
  collect_process_names: false       # no process names in connections or events
  collect_executable_paths: false    # no executable paths
  collect_usernames: false           # no account names
  collect_remote_hostnames: false    # no reverse DNS
  anonymize_local_addresses: true    # store 192.168.1.0/24 instead of 192.168.1.20

connections:
  enabled: false                     # no connection monitoring at all
destinations:
  enabled: false                     # no destination history
```

With `connections.enabled: false`, iPulse still measures availability, latency, loss,
DNS, speed, interfaces, Wi-Fi and outages: everything about the connection, nothing about
what is using it.

`destinations.ignore_destinations` and `destinations.ignore_processes` exclude specific
addresses, networks or applications from being recorded at all.

## Deleting data

```bash
sudo systemctl stop ipulse
sudo rm -f /var/lib/ipulse/ipulse.db*
sudo rm -f /var/log/ipulse/*
sudo systemctl start ipulse
```

Or remove everything, including the account:

```bash
sudo ipulse service uninstall --purge
```

## Multi-user and shared machines

On a shared machine iPulse records the connections of every user, and with process
attribution enabled it records which account owns each one. That is a meaningful capture
of other people's activity. Consider:

* setting `privacy.collect_usernames: false` and `collect_process_names: false`
* setting `connections.enabled: false` entirely
* telling the people who use the machine, which may be a legal requirement where you are

iPulse has no opinion on your obligations, but it gives you the switches to meet them.

## Compliance notes

* **Data controller.** You are. iPulse is software running on your machine; the authors
  receive nothing.
* **Personal data.** IP addresses, usernames and process activity can be personal data
  under GDPR and similar regimes when they relate to identifiable people.
* **Retention.** Configurable per table, as above; the defaults are conservative for the
  most identifying records.
* **Access and erasure.** Everything is in one SQLite database you can query, export or
  delete.
* **No transfers.** No data is transferred to any third party by iPulse itself.
