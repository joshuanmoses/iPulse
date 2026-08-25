# iPulse

**Internet connection monitoring, network observability and anomaly detection — running
as a real service on Windows and Linux, storing everything locally.**

iPulse answers the question you actually have when the Internet feels wrong: *what is
broken, and is it me or them?* It measures availability, latency, jitter, loss and speed
continuously, watches what your machine is talking to, and when something breaks it runs
a layered diagnosis and tells you which layer failed — with the evidence attached.

```text
$ ipulse status

iPulse Internet Monitor

Service:            Running
Internet:           Online
Health Score:       94/100
Download:           487.2 Mbps
Upload:             41.8 Mbps
Latency:            18.6 ms
Jitter:             2.9 ms
Packet Loss:        0.0%
DNS:                12.4 ms
Public IP:          203.0.113.41
ISP:                AS64496 Example Networks
Interface:          eth0
Last Speed Test:    2 minutes ago
Availability (24h): 99.986% (1 outage)
```

## The dashboard

Once the agent is running, the dashboard is at <http://127.0.0.1:8750>, bound to loopback
by default. It has six views:

| View | Shows |
|---|---|
| Overview | Status, health score, live quality and recent events |
| Speed | Download and upload over time, against your ISP plan |
| Latency | RTT, jitter, packet loss and DNS |
| Availability | Outages with duration and probable cause |
| Connections | Searchable process/destination table |
| Events | Syslog-style viewer with filters |

No screenshots are checked in yet; [Installation](#installation) gets you a running
instance in two commands.

## What it does

**Connection quality, continuously.** Health checks every 15 seconds, DNS and latency
every 30, a lightweight throughput probe every 5 minutes, a full speed test every 30.
Every interval is configurable, and iPulse never runs bandwidth-saturating tests on a
loop.

**Speed testing that means something.** Multi-stream download and upload with a discarded
warm-up, bounded by both time and a byte cap so a fast link cannot burn a metered
allowance. Results are compared against your advertised ISP plan and against
time-of-day-aware historical baselines, with mean, median, min, max, percentiles and
standard deviation over the hour, day, week and month.

**Outage diagnosis, not just outage detection.** When connectivity fails, iPulse tests
each layer independently and reports the lowest broken one:

```text
local device → network interface → default gateway → DNS → ISP → Internet
```

The result is a classification (`ISP_OUTAGE`, `DNS_FAILURE`, `GATEWAY_FAILURE`,
`LOCAL_INTERFACE_FAILURE`, `PARTIAL_CONNECTIVITY`, `WIFI_DEGRADATION`, …) with the
evidence that produced it, stored alongside the outage's start, end and duration.

**Traffic and connection observability.** Interface throughput with counter-reset
handling, active TCP and UDP connections attributed to the processes that own them,
destination history with reverse DNS and optional ASN enrichment, and detection of new,
rare, high-volume and unexpectedly-ported destinations.

**Anomaly detection you can audit.** Time-aware adaptive baselines (a Tuesday afternoon
is compared with other weekday afternoons, not with 3 AM on Sunday), deterministic
deviation rules with persistence and hysteresis, and an event-correlation engine that
replaces a list of symptoms with one conclusion:

```text
2026-08-24T14:47:22-05:00 WARN IPULSE-2107 LOCAL_BANDWIDTH_SATURATION
Direction=upload
CurrentLatency=73.0ms
PacketLoss=2.1%
PeakUpload=94.2Mbps
TopProcess=backup-agent
ProbableCause="LOCAL BANDWIDTH SATURATION"
Evidence="BANDWIDTH_SPIKE_UPLOAD(CurrentRate=94.0Mbps) + LATENCY_DEGRADATION(Deviation=305%) + PACKET_LOSS_DETECTED(PacketLoss=2.1%)"
```

**Security signals, stated carefully.** Threat-intelligence matching against indicators
you import (no vendor assumed, no feed shipped), and lateral-movement heuristics for host
sweeps, port scans and remote-administration probing. Every finding carries a confidence
and says what it does *not* mean. iPulse never blocks traffic and never claims a match is
confirmed malicious activity.

## Architecture

```text
                       ┌─────────────────────────────────────────────┐
  systemd / SCM  ────▶  │  Service Manager  →  Agent  →  Scheduler    │
                       │                          │                  │
                       │        ┌─────────────────┴─────────────┐     │
                       │        │  connectivity · latency · DNS │     │
                       │        │  interfaces · Wi-Fi · traffic │     │
                       │        │  connections · destinations   │     │
                       │        │  speed test · public IP · route│    │
                       │        │  threat intel · lateral       │     │
                       │        └─────────────────┬─────────────┘     │
                       │                          │                  │
                       │   Bus → Baselines → Anomaly → Correlation    │
                       │                          │                  │
                       │              Events → Logging Engine         │
                       │                          │                  │
                       │        SQLite  ·  .log  ·  .jsonl  ·  OS log │
                       │                          │                  │
                       │                REST API + Dashboard          │
                       └─────────────────────────────────────────────┘
                                            ▲
   ipulse status / events / connections ────┘  (HTTP on 127.0.0.1:8750)
```

Every OS-specific mechanism lives behind `internal/platform`: Linux reads `/proc`,
`/sys`, netlink (nl80211) and the socket error queue; Windows calls `iphlpapi`, `wlanapi`
and the process/token APIs. Nothing else in the tree knows which platform it is on.
See [docs/architecture.md](docs/architecture.md).

## Installation

There are no pre-built downloads: every install starts from a source checkout and a
build. That is one command — iPulse is pure Go with no cgo, so the result is a single
self-contained binary with no runtime dependencies.

**Prerequisites:** Go 1.24 or later, `git` and `make`. Nothing else is needed for the
binary; the package and Windows steps below each name their own extra tool.

```bash
git clone https://github.com/ipulse/ipulse
cd ipulse
sudo dnf install golang -y
make build          # writes ./bin/ipulse
./bin/ipulse version
```

### Try it first, without installing anything

Portable mode keeps the configuration, database and logs inside one directory. It needs
no root, registers no service and writes nothing outside that directory, which makes it
the fastest way to confirm iPulse works on your host:

```bash
./bin/ipulse run --portable ./ipulse-home
```

Leave that running and open <http://127.0.0.1:8750>, or query it from another terminal:

```bash
IPULSE_HOME=./ipulse-home ./bin/ipulse status
```

`make run` does the same thing using `.ipulse-home` inside the repository. Ctrl-C stops
it; delete the directory and nothing remains. Every client command reads the same
`IPULSE_HOME`, and `ipulse config path` prints exactly which locations are in use.

### Linux — install as a systemd service

```bash
make build                  # if you have not already
sudo scripts/install.sh
systemctl status ipulse
ipulse status
```

Build as yourself and install as root, as above — `sudo make install` also works but
compiles as root and leaves root-owned files in `bin/`.

The script creates the unprivileged `ipulse` system account, installs the binary to
`/usr/local/bin/ipulse`, creates `/etc/ipulse`, `/var/lib/ipulse` and `/var/log/ipulse`
with restricted permissions, writes a default configuration **only if none exists**,
validates it before starting anything, then registers and starts the unit. Override the
location with `sudo PREFIX=/usr scripts/install.sh` and the account with `IPULSE_USER`.

Removal keeps your measurements unless you ask otherwise:

```bash
sudo scripts/uninstall.sh            # keeps /var/lib/ipulse and /var/log/ipulse
sudo scripts/uninstall.sh --purge    # deletes them, and the ipulse account
```

### Linux — build a `.deb` or `.rpm`, then install it

Packages are built from the cross-compiled binaries, so this step takes a little longer.
The `.deb` is assembled with `ar` and `tar` and needs no Debian tooling; `make rpm`
needs `rpmbuild` (`sudo dnf install rpm-build systemd-rpm-macros`, or `sudo apt install
rpm` on Debian and Ubuntu).

```bash
make deb rpm        # both, into dist/
ls dist/
```

Install the one that matches your distribution. File names carry the version, and the
RPM name also carries the distribution tag of the host that built it (`.fc44`, `.el9`
and so on), so install what `ls dist/` actually printed:

```bash
sudo dpkg -i dist/ipulse_1.0.0_amd64.deb                 # Debian, Ubuntu
sudo dnf install ./dist/ipulse-1.0.0-1.*.x86_64.rpm      # Fedora, RHEL, Rocky, Alma
sudo zypper install ./dist/ipulse-1.0.0-1.*.x86_64.rpm   # openSUSE

systemctl status ipulse
```

The packages install to `/usr/bin/ipulse`, ship `/etc/ipulse/ipulse.yaml` as a conffile
so an upgrade never overwrites local edits, and start the service only if the
configuration validates — a typo produces a clear message rather than a unit that fails
at every boot. Removing the package keeps `/var/lib/ipulse` and `/var/log/ipulse`; use
`sudo apt purge ipulse`, or delete those directories by hand, to discard the history.

For other architectures, call the package scripts directly:
`packaging/deb/build.sh arm64` (or `armhf`) and `packaging/rpm/build.sh aarch64`.

### Windows 10/11 and Server 2019+

The Windows binary cross-compiles from any host — Linux, macOS or Windows — so build it
first and install from an elevated PowerShell:

```bash
scripts/build.sh --all      # writes dist/windows-amd64/ipulse.exe (and arm64)
```

```powershell
# Run as Administrator, from the repository root
.\packaging\windows\install.ps1
Get-Service iPulse
ipulse status
```

That copies `ipulse.exe` into `C:\Program Files\iPulse`, creates
`C:\ProgramData\iPulse\{config,data,logs}` with permissions restricted to SYSTEM and
Administrators, writes a default configuration if none exists, adds the install directory
to the system `PATH` and registers the **iPulse** service.
`.\packaging\windows\uninstall.ps1` reverses all of it.

No MSI is shipped, but you can build one on a Windows host with the WiX Toolset
(`dotnet tool install --global wix`):

```powershell
.\packaging\windows\build.ps1 -Architecture x64   # writes dist\ipulse-1.0.0-x64.msi
msiexec /i dist\ipulse-1.0.0-x64.msi              # add /qn for a silent install
```

Portable mode works the same way on Windows and needs no Administrator:

```powershell
.\dist\windows-amd64\ipulse.exe run --portable C:\Users\me\ipulse-home
```

Full details: [Linux](docs/installation-linux.md) · [Windows](docs/installation-windows.md)

## Basic commands

A service install puts `ipulse` on your `PATH`. Before that — or in portable mode — call
the binary you built, `./bin/ipulse`, and set `IPULSE_HOME` so the client reads the same
directory the agent is writing to.

```bash
ipulse status                  # current state at a glance
ipulse test                    # connectivity, DNS and latency, now
ipulse test speed              # a full speed test, now
ipulse test route              # measure the path to a destination
ipulse diagnostics             # run the layered diagnostic ladder
ipulse diagnostics --privileges  # what iPulse can and cannot do here, and why

ipulse events --severity warning --since 24h
ipulse events --category security --since 7d
ipulse events -f                       # follow, like tail -f
ipulse events catalog --code 3004      # explain an event ID

ipulse connections --top               # per-process activity
ipulse destinations --new 24h          # destinations first seen today
ipulse destinations --flagged          # threat-intelligence matches

ipulse config                          # effective configuration
ipulse config validate                 # check a file before applying it
ipulse start | stop | restart          # service control
ipulse version
```

Every command takes `--json` for scripting, and `ipulse help <command>` documents the
rest. Client commands read the local database directly, so they work whether or not the
service is running — but the database is only created once the agent has run at least
once.

## Configuration

`/etc/ipulse/ipulse.yaml` on Linux, `C:\ProgramData\iPulse\config\ipulse.yaml` on
Windows, and `<dir>/config/ipulse.yaml` in portable mode. `ipulse config path` prints the
locations actually in effect, and `ipulse config init` writes a default file if none
exists. The one setting worth changing immediately is your ISP plan, which is what turns
"487 Mbps" into "97 % of what you pay for":

```yaml
speed_test:
  expected_download_mbps: 500
  expected_upload_mbps: 50
```

Unknown keys are rejected rather than ignored, and `ipulse config validate` reports every
problem at once. See [docs/configuration.md](docs/configuration.md) for every option.

## Building from source

Requires Go 1.24 or later. There are no cgo dependencies, so one command produces a
static binary for any supported platform — including cross-compiling the Windows build
from Linux. See [Installation](#installation) for the full first-run walkthrough.

```bash
make build          # host platform, into bin/
make build-all      # linux amd64/arm64/arm and windows amd64/arm64, into dist/
make run            # build, then run in the foreground from ./.ipulse-home
make install        # build, then install the service (needs root)
make uninstall      # stop and remove the service (needs root)
make deb rpm        # packages, into dist/ (rpm needs rpmbuild)
make test           # vet, format check, cross-compile check, full test suite
make docs           # regenerate docs/event-catalog.md from the code
make clean          # remove bin/, dist/ and .ipulse-home/
make help           # every target
```

`make build-all` clears `dist/` before it writes, so build every package you want in a
single `make deb rpm` invocation rather than one target at a time.

The scripts underneath work standalone if you would rather not use `make`:
`scripts/build.sh [--all | --platform linux/arm64]`, `scripts/install.sh`,
`scripts/uninstall.sh`, `scripts/test.sh`, `packaging/deb/build.sh`,
`packaging/rpm/build.sh` and, on Windows, `packaging/windows/build.ps1`.

## Testing

```bash
make test           # everything
make test-short     # skip the tests that use the network
make race           # with the race detector
make cover          # with a coverage summary
```

The suite runs offline. Outages, packet loss, saturation, scans and threat matches are
all simulated through the detection pipeline rather than requiring a real fault:

```bash
go test ./internal/agent/ -run TestSimulate -v
```

See [docs/development.md](docs/development.md).

## Privacy

iPulse collects **metadata only**. It records that a process connected to an address on a
port, how long it lasted, and what the connection quality was. It does not capture packet
payloads, HTTP bodies, TLS plaintext, documents or keystrokes, and it performs no TLS
interception — `privacy.payload_inspection` exists solely so that setting it to true is
*rejected* by configuration validation.

Nothing leaves the machine unless you ask it to. There is no cloud account, no telemetry,
no analytics and no phone-home. The only outbound traffic is the measurement traffic you
configure: probe targets, speed-test endpoints, public-IP providers, and any threat feeds
you add. Every identity field — process names, executable paths, usernames, reverse DNS —
has its own switch.

See [docs/privacy.md](docs/privacy.md).

## Security

The service does not run as root on Linux. It runs as a dedicated unprivileged account
with two capabilities — `CAP_NET_RAW` for ICMP and path measurement, and
`CAP_DAC_READ_SEARCH` for process attribution — under a hardened unit
(`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, a syscall filter and a
restricted address-family list). On Windows it runs as LocalSystem because the extended
socket tables and the WLAN API require it.

The API and dashboard are bound to loopback, protected by a Host allow-list that defeats
DNS rebinding, and refuse to bind anywhere else without an authentication token.
Configuration input is validated, log values are sanitised so a hostile process name
cannot forge a log record, and no part of iPulse invokes a shell.

`ipulse diagnostics --privileges` prints exactly what is available on your host and what
each missing privilege costs. See [docs/security.md](docs/security.md).

## Documentation

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Design, module map, platform boundary, data flow |
| [installation-linux.md](docs/installation-linux.md) | Packages, manual install, systemd, upgrades |
| [installation-windows.md](docs/installation-windows.md) | MSI, PowerShell, the service, upgrades |
| [configuration.md](docs/configuration.md) | Every option, with defaults and guidance |
| [event-catalog.md](docs/event-catalog.md) | Every event iPulse can emit (generated from the code) |
| [detection-engine.md](docs/detection-engine.md) | Baselines, thresholds and correlation rules, in full |
| [api.md](docs/api.md) | REST API reference |
| [security.md](docs/security.md) | Privilege matrix, hardening, threat model |
| [privacy.md](docs/privacy.md) | What is collected, what is not, and how to reduce it |
| [troubleshooting.md](docs/troubleshooting.md) | Symptoms, causes and fixes |
| [development.md](docs/development.md) | Building, testing, adding a collector or a provider |

## Design principles

1. Low resource use: one process, bounded queues, no busy loops.
2. Works offline apart from the probes that inherently need the Internet.
3. No mandatory cloud account or external service.
4. Local-first storage.
5. Human-readable logs.
6. Transparent detection: every rule is documented and deterministic.
7. Cross-platform by construction.
8. Extensible providers for speed testing, enrichment and threat intelligence.
9. No vendor lock-in.
10. Privacy by default.
11. Never describe an anomaly as confirmed malicious activity.

## Licence

MIT. See [LICENSE](LICENSE).
