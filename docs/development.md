# Development

## Requirements

- Go 1.24 or later (developed against 1.27)
- `git`, `make`
- Nothing else. There is no C toolchain requirement: every dependency is pure Go and all
  builds are `CGO_ENABLED=0`, including SQLite (`modernc.org/sqlite`). That is what makes
  a single static binary per platform possible.

Optional, only for packaging: `dpkg-deb` (the `.deb` script falls back to `ar` and `tar`),
`rpmbuild`, and the WiX Toolset v4 on Windows.

```bash
git clone https://github.com/ipulse/ipulse
cd ipulse
make build
./dist/ipulse version
```

## The loop

```bash
make build            # dist/ipulse for this platform
make test             # vet, gofmt check, cross-compile check, full suite
make test-short       # skip the tests that touch the network
make race             # the suite under the race detector
make cover            # coverage.html
make fmt              # gofmt -w
make lint             # go vet plus the gofmt check
make build-all        # linux amd64/arm64/arm, windows amd64/arm64
make packages         # .deb and .rpm
make docs             # regenerate docs/event-catalog.md from the code
make clean
```

Run the agent without installing anything:

```bash
./dist/ipulse run --portable ./run
```

Portable mode keeps configuration, database and logs under one directory, so a working
tree never writes to `/etc` or `/var`. The dashboard comes up on
<http://127.0.0.1:8750>.

`make test` is the gate. It is what CI runs and what must pass before a commit.

## Layout

```text
cmd/ipulse/          the command line: one file per command, plus env and output helpers
internal/
  agent/             the agent: scheduler, event bus, state, and one file per monitor
  api/               REST handlers and routing
  anomaly/           detection rules and the persistence/cooldown gate
  baseline/          learned normals: Welford accumulators, EWMA, MAD, time buckets
  config/            schema, defaults, validation, loading, platform paths
  connectivity/      reachability probes, outage classification, the diagnostic ladder
  correlation/       the rules that turn several events into one conclusion
  database/          SQLite schema, models and per-domain stores
  destinations/      destination profiling and the new/rare/fan-out analysis
  dns/               resolver probing (package dnsmon)
  events/            severity, category, the event catalog and rendering
  health/            the composite health score
  interfaces/        interface and route change tracking
  latency/           ICMP and TCP round-trip measurement
  lateral/           lateral-movement heuristics and confidence grading
  logging/           the logger and its sinks (file, JSONL, database, syslog, Event Log)
  network/           the connection collector
  platform/          the OS abstraction: facade, types/, linux/, windows/
  publicip/          public address discovery and ASN lookup
  routing/           traceroute
  security/          sanitising, file permissions, the privilege report
  service/           service lifecycle: systemd, Windows SCM, unit generation
  speedtest/         the throughput engine and its HTTP provider
  threatintel/       feed parsing, import and matching
  traffic/           interface sampling, windows, self-traffic exclusion
  util/              statistics and address helpers
web/                 the dashboard, embedded with go:embed
tests/               cross-cutting integration tests
configs/             the reference configuration
docs/                this documentation
packaging/           deb, rpm and WiX
scripts/             build, test, install, uninstall
```

Unit tests live beside the code they test. `tests/` holds the cross-cutting ones: a
full agent lifecycle, the API surface, and the packaging manifests.

## Rules the codebase follows

**Nothing OS-specific outside `internal/platform`.** No build tags, no `/proc` paths, no
`syscall` imports anywhere else. Every collector talks to `platform.Provider`. This is
what lets the Linux code be reviewed on Windows and vice versa, and the cross-compile
step in `make test` is the check: it builds every release target, so an OS-specific
import in shared code fails immediately rather than at release time.

**Types live in `internal/platform/types`.** The facade re-exports them as aliases. The
leaf package exists to break the cycle between the facade and the implementations; do not
import it directly from collectors — use `platform.Interface`, not `types.Interface`.

**No shelling out.** Interfaces, routes, sockets, wireless state and DNS configuration all
come from native APIs — netlink and `/proc` on Linux, `iphlpapi` and `wlanapi` on
Windows. There is no `exec.Command` in a collector path, which removes command injection
as a category and makes behaviour predictable when `PATH` is unusual.

**Missing privilege degrades, never fails.** A capability that is unavailable is reported
through `Capabilities()` and the affected collector falls back (ICMP to TCP timing,
attributed connections to unattributed) and records which method it used. Nothing
silently produces a worse number under the same label.

**Events come from the catalog.** Every event has an ID, a severity, a category, a
documented trigger, documented fields and a suggested action. `docs/event-catalog.md` is
generated from the catalog, so it cannot drift.

**Field values are stored raw; quoting happens at render time.** `Field.Render()` applies
sanitising and quoting for the text format. The database and the JSON Lines output hold
the actual value.

**Detection states possibility, not fact.** "Possible lateral scanning behavior detected",
with the evidence and a confidence grade. No rule asserts compromise.

## Adding an event

Add it to `internal/events/catalog_defs.go` in the right reserved range:

| Range | Category |
|---|---|
| 1000–1999 | connectivity |
| 2000–2999 | performance |
| 3000–3999 | availability |
| 4000–4999 | traffic |
| 5000–5999 | security |
| 6000–6999 | DNS and routing |
| 7000–7999 | interface |
| 8000–8999 | service |
| 9000–9999 | internal |

```go
{
    Code:     2110,
    Name:     "UPSTREAM_PERFORMANCE_DEGRADATION",
    Severity: Warning,
    Category: CategoryPerformance,
    Summary:  "Several metrics degraded together beyond the local network.",
    Trigger:  "Latency, loss and throughput all breached while the gateway stayed healthy.",
    Fields:   []string{"AffectedMetrics", "GatewayHealthy", "Confidence"},
    Action:   "Compare with the ISP status page; the evidence points upstream.",
},
```

Emit it with the builder, which enforces the documented fields:

```go
ev := events.New(events.UpstreamPerformanceDegradation).
    Add("AffectedMetrics", strings.Join(metrics, ",")).
    Add("GatewayHealthy", "true").
    AddUnit("LatencyMs", latency, "ms").
    AddPercent("PacketLossPct", loss)
a.emit(ev)
```

Then `make docs` and commit the regenerated catalog. A test checks that every emitted
event is in the catalog and that its fields match.

## Adding a collector

A monitor is anything with a name and a set of scheduled tasks:

```go
type Monitor interface {
    Name() string
    Tasks() []Task
}
```

1. Write `internal/agent/monitor_<name>.go`:

```go
type exampleMonitor struct {
    a    *Agent
    gate *gate
}

func newExampleMonitor(a *Agent) *exampleMonitor {
    return &exampleMonitor{a: a, gate: a.newGate()}
}

func (m *exampleMonitor) Name() string { return "example" }

func (m *exampleMonitor) Tasks() []Task {
    return []Task{{
        Name:       "example",
        Interval:   m.a.cfg.Monitoring.ExampleInterval.D(),
        Timeout:    m.a.cfg.Monitoring.ProbeTimeout.D() * 2,
        Jitter:     m.a.cfg.Monitoring.Jitter.D(),
        RunOnStart: true,
        Fn:         m.run,
    }}
}

func (m *exampleMonitor) run(ctx context.Context) error {
    // measure, store, then decide whether to report
}
```

2. Register it in `buildMonitors` in `internal/agent/build_monitors.go`, guarded by its
   `enabled` setting.
3. Add the configuration in `internal/config`: the struct field with its YAML and JSON
   tags, the default in `defaults.go`, and validation in `validate.go`. Add it to
   `configs/ipulse.yaml` — a test fails if the reference file and the defaults disagree.
4. Add the storage in `internal/database`: a schema migration and a store method.
5. Document the options in `configuration.md`.

Use `a.newGate()` rather than reporting directly. The gate applies persistence, cooldown
and recovery hysteresis, which is why iPulse does not flap.

Set `ManualOnly: true` for a task that should be triggered from the API or the CLI rather
than scheduled.

## Adding a speed-test provider

Implement `speedtest.Provider` and register it from `init()`:

```go
func init() { speedtest.Register(&myProvider{}) }

func (p *myProvider) Name() string { return "myprovider" }

func (p *myProvider) Prepare(ctx context.Context, ep speedtest.Endpoint,
    timeout time.Duration) (speedtest.Session, error) {
    // validate the endpoint; do not measure here
}
```

A `Session` performs `Download` and `Upload` and reports a `Throughput`. Select it with
`speed_test.provider`. The engine owns byte caps, stream management, warm-up discard and
self-traffic accounting, so a provider only has to move bytes and report how many.

Keep the constraint in mind: iPulse must never depend on one commercial API. Any new
provider is an addition, never a replacement for the plain HTTP one.

## Adding a platform capability

1. Add the method to `Provider` in `internal/platform/platform.go` and any types to
   `internal/platform/types`.
2. Implement it in `internal/platform/linux` and `internal/platform/windows`.
3. Return `types.ErrUnsupported` from `provider_other.go` so unsupported platforms still
   compile and degrade cleanly.
4. Add a capability flag if callers need to know before calling, and extend the privilege
   report in `internal/security` so `ipulse diagnostics --privileges` shows it.
5. `make test` to confirm every release target still compiles.

## Testing

**No test may require a real outage, and none may require the Internet by default.**
Failures are simulated: `internal/agent/testsupport_test.go` provides a fake clock, a
scripted platform provider and an in-memory database, so an outage, a route change, a
DNS failure or a scan is produced deterministically.

- `internal/agent/simulation_test.go` — outage detection, recovery, degradation
- `internal/agent/security_simulation_test.go` — scanning, new destinations, threat matches
- `internal/agent/correlation_integration_test.go` — correlation end to end
- `tests/` — the agent lifecycle, the API surface, packaging manifests

Tests that do use the network are guarded by `testing.Short()` and excluded from
`make test-short`.

```bash
go test ./internal/agent/ -run TestOutage -v
go test ./... -count=1
```

Rules for new tests: no `time.Sleep` for synchronisation — use the fake clock or a
channel; no reliance on wall-clock time — pass the timestamp in; use `t.TempDir()` for
databases and files; and assert on the event ID and the fields, not on the rendered text.

## Cross-compiling

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/ipulse
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/ipulse
```

Version metadata is stamped at link time:

```bash
go build -ldflags "-s -w \
  -X github.com/ipulse/ipulse/internal/version.Version=$(cat VERSION) \
  -X github.com/ipulse/ipulse/internal/version.Commit=$(git rev-parse --short HEAD) \
  -X github.com/ipulse/ipulse/internal/version.BuildTime=$(date -u +%FT%TZ)" \
  ./cmd/ipulse
```

`scripts/build.sh` does this for every target.

## Dashboard

`web/assets/` is embedded with `go:embed` and served by `internal/api`. It is vanilla
JavaScript with hand-drawn SVG charts: no build step, no bundler, no `node_modules`, and
no external requests — which is also what lets the Content-Security-Policy be strict.

Edit the assets and rebuild. For a faster loop, run the agent in portable mode and reload
the page; assets are embedded at build time, so a rebuild is needed for each change.

## Packaging

```bash
make packages                              # .deb and .rpm into dist/
bash packaging/deb/build.sh                # .deb alone
bash packaging/rpm/build.sh                # .rpm alone
pwsh packaging/windows/build.ps1           # .msi (needs WiX v4)
```

The Linux packages install the same unit that `ipulse service install` writes; the MSI
registers the service by invoking `ipulse service install`. That is deliberate: a
packaged installation and a manual one cannot diverge.

Check a built package before releasing:

```bash
dpkg-deb -c dist/ipulse_1.0.0_amd64.deb
rpm -qlp dist/ipulse-1.0.0-1.x86_64.rpm
```

## Before committing

```bash
make test
```

That runs `go vet`, the gofmt check, the cross-compile check for every release target and
the full suite. Also worth a moment:

- Does a new configuration option have a default, validation, a reference-file entry and
  documentation?
- Does a new event appear in the catalog, and is `docs/event-catalog.md` regenerated?
- Does a new detection rule use a gate, and does it describe possibility rather than fact?
- Does anything new log a value that came from the network? It must go through
  `security.SanitizeValue`.
- Does anything new write a file? It must use `security` for permissions.

## Security review checklist

The constraints in [security.md](security.md) and [privacy.md](privacy.md) are
requirements, not preferences. In particular: no payload inspection, no TLS interception,
no automatic blocking, no cloud telemetry, no plaintext credentials, no shelling out where
a native API exists, and the dashboard bound to loopback unless a token is configured.

A change that would relax any of those needs to be argued in the pull request, not slipped
in.
