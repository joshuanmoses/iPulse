# Installing iPulse on Windows

Supported: Windows 10, Windows 11, Windows Server 2019, 2022 and 2025, on x64 and arm64.

## MSI installer

```powershell
msiexec /i ipulse-1.0.0-x64.msi
```

Silent, for deployment:

```powershell
msiexec /i ipulse-1.0.0-x64.msi /qn /l*v install.log
```

The installer copies `ipulse.exe` into `C:\Program Files\iPulse`, creates
`C:\ProgramData\iPulse\{config,data,logs}` with permissions restricted to SYSTEM and
Administrators, writes a default configuration if none exists, adds the install directory
to the system `PATH`, registers the **iPulse** service and starts it.

The service is registered by running the binary rather than by an MSI table, so an
MSI-installed service and a `ipulse service install` one are identical: same automatic
delayed start, same recovery actions, same Event Log source.

```powershell
Get-Service iPulse
ipulse status
```

## PowerShell installer

For a binary without an MSI, or for scripted deployment:

```powershell
# Run as Administrator
.\packaging\windows\install.ps1
.\packaging\windows\install.ps1 -BinaryPath .\ipulse.exe -NoStart
```

## Portable mode

No installation, no service, no Administrator:

```powershell
.\ipulse.exe run --portable C:\Users\me\ipulse-home
```

## After installing

Set your ISP plan, which is what turns a raw number into a judgement:

```powershell
notepad C:\ProgramData\iPulse\config\ipulse.yaml
```

```yaml
speed_test:
  expected_download_mbps: 500
  expected_upload_mbps: 50
```

```powershell
ipulse config validate
Restart-Service iPulse
ipulse status
```

The dashboard is at <http://127.0.0.1:8750> and is bound to loopback.

## What gets installed where

| Path | Purpose |
|---|---|
| `C:\Program Files\iPulse\ipulse.exe` | the binary (service and CLI) |
| `C:\ProgramData\iPulse\config\ipulse.yaml` | configuration |
| `C:\ProgramData\iPulse\data\ipulse.db` | SQLite database |
| `C:\ProgramData\iPulse\logs\ipulse.log` | human-readable log |
| `C:\ProgramData\iPulse\logs\ipulse.jsonl` | JSON Lines log |
| Event Log → Application, source `iPulse` | significant events |

The data and log directories do not inherit ProgramData's default permissions: they are
set to SYSTEM and Administrators only, because they contain connection metadata.

## Why the service runs as LocalSystem

Three of iPulse's functions need it on Windows:

* `GetExtendedTcpTable` / `GetExtendedUdpTable` return the owning process for every
  socket on the system, and opening those processes to read their image path requires
  more rights than a limited account has.
* The WLAN API (`wlanapi.dll`) requires a session with access to the WLAN service.
* ICMP echo through a raw socket requires Administrator.

The exposure this creates is bounded deliberately: the API and dashboard stay bound to
loopback, the service accepts no remote input, and it never executes anything it reads.
See [security.md](security.md).

To run with less, install with `--no-start`, change the service account in
`services.msc`, and accept that connection attribution, Wi-Fi telemetry and ICMP will
report themselves unavailable. `ipulse diagnostics --privileges` shows exactly what was
lost.

## Service management

```powershell
Start-Service iPulse
Stop-Service iPulse
Restart-Service iPulse
Get-Service iPulse | Format-List *

# or through the binary
ipulse start
ipulse stop
ipulse service status
```

Failure recovery is configured at install time: two automatic restarts (after 30 and 60
seconds), then the failure is left visible rather than looping forever.

## Reading the logs

```powershell
Get-Content C:\ProgramData\iPulse\logs\ipulse.log -Tail 50 -Wait
ipulse events --severity warning --since 24h
ipulse events -f

# significant events also reach the Windows Event Log
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='iPulse']]]" -MaxEvents 20
Get-WinEvent -ProviderName iPulse | Where-Object Id -eq 3001    # outages
```

The Event Log entry ID is the iPulse event ID, so the same identifiers work in Windows
tooling and in the iPulse log files.

## Windows Firewall

iPulse makes outbound connections only and needs no inbound rule. The dashboard listens
on loopback, which the firewall does not filter.

If you deliberately bind the dashboard to a LAN address (which requires
`dashboard.auth_token` and is validated as such), add a rule scoped to the addresses that
should reach it:

```powershell
New-NetFirewallRule -DisplayName "iPulse dashboard" -Direction Inbound `
  -Protocol TCP -LocalPort 8750 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Upgrading

```powershell
msiexec /i ipulse-1.1.0-x64.msi     # upgrades in place, keeps all data
```

The database migrates automatically; the configuration is never overwritten.

## Uninstalling

```powershell
msiexec /x ipulse-1.0.0-x64.msi          # keeps historical data
.\packaging\windows\uninstall.ps1         # same
.\packaging\windows\uninstall.ps1 -Purge  # removes C:\ProgramData\iPulse too
```

Or through the binary:

```powershell
ipulse service uninstall --keep-data
ipulse service uninstall --purge
```

## Building the MSI yourself

Requires the WiX Toolset v4 or later:

```powershell
dotnet tool install --global wix
.\packaging\windows\build.ps1 -Architecture x64
```

The binary is cross-compiled from any host with `scripts/build.sh --all`, so the machine
building the MSI needs no Go toolchain.
