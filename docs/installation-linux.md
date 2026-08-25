# Installing iPulse on Linux

iPulse targets systemd-based distributions for service management. The agent itself runs
anywhere Go runs; only `ipulse service install` requires systemd, and `ipulse run` is
always available as an alternative.

Supported: Debian 11+, Ubuntu 20.04+, Fedora 36+, RHEL/Rocky/Alma 8+, openSUSE Leap 15+,
Arch, and any distribution with systemd 245 or later. Architectures: amd64, arm64 and
armv7 (a Raspberry Pi is a perfectly good iPulse host).

## Debian and Ubuntu

```bash
sudo dpkg -i ipulse_1.0.0_amd64.deb
```

The package creates the `ipulse` system account, installs the binary to `/usr/bin/ipulse`,
writes `/etc/ipulse/ipulse.yaml` (only if absent), registers `ipulse.service` and starts
it. If the configuration fails validation the package installs but does not start the
service, and says so.

```bash
systemctl status ipulse
ipulse status
```

Removal keeps your measurements:

```bash
sudo apt remove ipulse      # keeps /var/lib/ipulse and /var/log/ipulse
sudo apt purge ipulse       # removes them, and the ipulse account
```

## Fedora, RHEL and openSUSE

```bash
sudo rpm -i ipulse-1.0.0-1.x86_64.rpm
# or
sudo dnf install ./ipulse-1.0.0-1.x86_64.rpm
```

```bash
sudo rpm -e ipulse          # keeps /var/lib/ipulse and /var/log/ipulse
```

Historical data is never removed by an RPM erase; delete `/var/lib/ipulse` and
`/var/log/ipulse` by hand if you want it gone.

## Any distribution, from a binary

```bash
tar xzf ipulse-1.0.0-linux-amd64.tar.gz
sudo ./scripts/install.sh
```

The script does exactly what the packages do: creates the account, installs the binary,
creates the directories with tight permissions, writes a default configuration if none
exists, validates it, and registers the service.

Useful variables:

```bash
sudo IPULSE_USER=netmon PREFIX=/opt/ipulse ./scripts/install.sh
```

## Portable mode

No installation, no service, no root, nothing outside one directory:

```bash
ipulse run --portable ~/ipulse-home
```

Configuration, database and logs all live under that directory. This is the right way to
try iPulse, to run it in a container, or to keep it entirely inside a user's home.

## After installing

The single most valuable change is telling iPulse what you pay for, which turns a raw
number into a judgement:

```bash
sudo nano /etc/ipulse/ipulse.yaml
```

```yaml
speed_test:
  expected_download_mbps: 500
  expected_upload_mbps: 50
```

```bash
sudo ipulse config validate     # check before applying
sudo systemctl restart ipulse
ipulse status
```

Open the dashboard at <http://127.0.0.1:8750>. It is bound to loopback; see
[security.md](security.md) before changing that.

## What gets installed where

| Path | Purpose | Permissions |
|---|---|---|
| `/usr/bin/ipulse` | the binary (agent and CLI) | `0755 root:root` |
| `/etc/ipulse/ipulse.yaml` | configuration | `0640 root:ipulse` |
| `/var/lib/ipulse/ipulse.db` | SQLite database | `0640 ipulse:ipulse` |
| `/var/log/ipulse/ipulse.log` | human-readable log | `0640 ipulse:ipulse` |
| `/var/log/ipulse/ipulse.jsonl` | JSON Lines log | `0640 ipulse:ipulse` |
| `/lib/systemd/system/ipulse.service` | unit file | `0644 root:root` |

The data directory is not world-readable: it contains connection metadata.

## The systemd unit

Print exactly what would be installed, without installing it:

```bash
ipulse service unit
```

The unit runs as the unprivileged `ipulse` account with two capabilities:

* `CAP_NET_RAW` — ICMP latency, packet loss and path measurement. Without it, iPulse
  falls back to TCP connect timing and disables path measurement.
* `CAP_DAC_READ_SEARCH` — reading `/proc/<pid>/fd` so connections can be attributed to
  the processes that own them. Without it, connections are still recorded, but without a
  process name.

Everything else is confined: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp`,
`PrivateDevices`, `NoNewPrivileges`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, and `RestrictAddressFamilies` limited to
`AF_INET AF_INET6 AF_UNIX AF_NETLINK`. Memory is capped at 256 MB and tasks at 64.

To run without either capability, drop the `AmbientCapabilities` and
`CapabilityBoundingSet` lines with a drop-in:

```bash
sudo systemctl edit ipulse
```

```ini
[Service]
AmbientCapabilities=
CapabilityBoundingSet=
```

`ipulse diagnostics --privileges` then shows precisely what has been lost.

## Service management

```bash
sudo systemctl start|stop|restart ipulse
sudo systemctl enable|disable ipulse
systemctl status ipulse
journalctl -u ipulse -f              # significant events reach journald
journalctl -u ipulse -p warning      # warnings and above
```

iPulse also drives systemd directly:

```bash
sudo ipulse start
sudo ipulse stop
ipulse service status
```

## Reloading configuration

Thresholds, baselines, correlation, health weights, ISP expectations and the log level
apply on reload. Bind address, database path, log directory and monitoring intervals need
a restart, and the reload event lists which of those changed.

```bash
sudo systemctl reload ipulse     # or: sudo kill -HUP $(pidof ipulse)
```

An invalid configuration is rejected and the previous one stays in force, with an
`IPULSE-8005 CONFIG_INVALID` event listing every problem.

## Upgrading

```bash
sudo dpkg -i ipulse_1.1.0_amd64.deb    # or rpm -U
```

The database migrates automatically and forwards-only; the configuration is a conffile
and is never overwritten. Baselines and history survive the upgrade.

## Running in a container

```dockerfile
FROM scratch
COPY ipulse /ipulse
ENV IPULSE_HOME=/data
VOLUME /data
EXPOSE 8750
ENTRYPOINT ["/ipulse", "run"]
```

```bash
docker run --rm -v ipulse-data:/data -p 127.0.0.1:8750:8750 \
  --cap-add NET_RAW ipulse
```

Notes for containers:

* `--cap-add NET_RAW` enables ICMP; without it, latency falls back to TCP timing.
* Process attribution needs the host PID namespace (`--pid host`) and `/proc`, so it is
  usually left off in containers. iPulse reports the limitation once at start-up.
* Use `--network host` if you want the container to measure the host's interfaces rather
  than its own virtual one.

## Uninstalling

```bash
sudo scripts/uninstall.sh            # keeps data
sudo scripts/uninstall.sh --purge    # removes everything, including the account
```

Or through the binary:

```bash
sudo ipulse service uninstall --keep-data
sudo ipulse service uninstall --purge
```
