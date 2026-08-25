package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigValidates(t *testing.T) {
	cfg := Default()
	cfg.ResolvedPaths()
	warns, err := cfg.Validate()
	if err != nil {
		t.Fatalf("default configuration must validate: %v", err)
	}
	// The only expected warning on a fresh install is the unset ISP expectation.
	for _, w := range warns {
		if !strings.Contains(w, "expected_download_mbps") {
			t.Errorf("unexpected default warning: %s", w)
		}
	}
}

// TestShippedReferenceConfigMatchesDefaults keeps configs/ipulse.yaml honest: it must
// parse under strict decoding (so no key has drifted) and produce the same effective
// configuration as the built-in defaults.
func TestShippedReferenceConfigMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "ipulse.yaml"))
	if err != nil {
		t.Skipf("reference config not available: %v", err)
	}
	got, _, err := Parse(data)
	if err != nil {
		t.Fatalf("shipped reference config must validate: %v", err)
	}
	want := Default()
	want.ResolvedPaths()

	if got.Monitoring != want.Monitoring {
		t.Errorf("monitoring section drifted:\n got %+v\nwant %+v", got.Monitoring, want.Monitoring)
	}
	if got.Alerts != want.Alerts {
		t.Errorf("alerts section drifted:\n got %+v\nwant %+v", got.Alerts, want.Alerts)
	}
	if got.Health != want.Health {
		t.Errorf("health section drifted:\n got %+v\nwant %+v", got.Health, want.Health)
	}
	if got.Logging != want.Logging {
		t.Errorf("logging section drifted:\n got %+v\nwant %+v", got.Logging, want.Logging)
	}
	if got.Baseline != want.Baseline {
		t.Errorf("baseline section drifted:\n got %+v\nwant %+v", got.Baseline, want.Baseline)
	}
	if got.Database.Retention != want.Database.Retention {
		t.Errorf("retention drifted:\n got %+v\nwant %+v", got.Database.Retention, want.Database.Retention)
	}
	if got.Dashboard.Port != want.Dashboard.Port || got.Dashboard.Address != want.Dashboard.Address {
		t.Errorf("dashboard bind drifted: %s:%d", got.Dashboard.Address, got.Dashboard.Port)
	}
	if len(got.SpeedTest.Endpoints) != len(want.SpeedTest.Endpoints) {
		t.Errorf("speed test endpoints drifted: %d vs %d", len(got.SpeedTest.Endpoints), len(want.SpeedTest.Endpoints))
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, _, err := Parse([]byte("monitoring:\n  health_intervalx: 10s\n"))
	if err == nil {
		t.Fatal("expected unknown key to be rejected")
	}
	if !strings.Contains(err.Error(), "health_intervalx") {
		t.Errorf("error should name the offending key: %v", err)
	}
}

func TestBareNumberDurationRejected(t *testing.T) {
	_, _, err := Parse([]byte("monitoring:\n  health_interval: 15\n"))
	if err == nil {
		t.Fatal("a bare number must not be accepted as a duration")
	}
	if !strings.Contains(err.Error(), "unit") {
		t.Errorf("error should explain the missing unit: %v", err)
	}
}

func TestDurationParsing(t *testing.T) {
	cfg, _, err := Parse([]byte("monitoring:\n  health_interval: 45s\n  full_interval: \n"))
	if err == nil {
		// full_interval is not a monitoring key; strict decoding must reject it.
		t.Fatal("expected strict decoding to reject misplaced key")
	}
	cfg, _, err = Parse([]byte("monitoring:\n  health_interval: 45s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitoring.HealthInterval.D() != 45*time.Second {
		t.Errorf("got %s, want 45s", cfg.Monitoring.HealthInterval)
	}
}

func TestValidationCollectsEveryProblem(t *testing.T) {
	_, _, err := Parse([]byte(`
monitoring:
  health_interval: 0s
latency:
  probes: 0
  method: bogus
dashboard:
  port: 99999
privacy:
  payload_inspection: true
`))
	if err == nil {
		t.Fatal("expected validation failure")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Problems) < 5 {
		t.Errorf("expected all problems reported at once, got %d: %v", len(ve.Problems), ve.Problems)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{"health_interval", "latency.probes", "latency.method", "dashboard.port", "payload_inspection"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems missing %q:\n%s", want, joined)
		}
	}
}

// TestNonLoopbackBindRequiresToken is a security-relevant default: the API may not be
// exposed off-host without authentication.
func TestNonLoopbackBindRequiresToken(t *testing.T) {
	_, _, err := Parse([]byte("dashboard:\n  address: 0.0.0.0\n"))
	if err == nil {
		t.Fatal("expected non-loopback bind without a token to be rejected")
	}
	if !strings.Contains(err.Error(), "auth_token") {
		t.Errorf("error should require auth_token: %v", err)
	}
	cfg, warns, err := Parse([]byte("dashboard:\n  address: 0.0.0.0\n  auth_token: 0123456789abcdef0123\n"))
	if err != nil {
		t.Fatalf("token should make the bind acceptable: %v", err)
	}
	if len(warns) == 0 {
		t.Error("expected a warning about exposing the API off-host")
	}
	if !containsHost(cfg.Dashboard.AllowedHosts, "0.0.0.0") {
		t.Errorf("normalisation should add the bind address to allowed_hosts: %v", cfg.Dashboard.AllowedHosts)
	}
}

func TestPayloadInspectionAlwaysRejected(t *testing.T) {
	_, _, err := Parse([]byte("privacy:\n  payload_inspection: true\n"))
	if err == nil {
		t.Fatal("payload inspection must be rejected: iPulse performs no payload capture")
	}
}

func TestWorldWritableLogModeRejected(t *testing.T) {
	if _, _, err := Parse([]byte("logging:\n  file_mode: \"0666\"\n")); err == nil {
		t.Fatal("expected group/other-writable log mode to be rejected")
	}
	if _, warns, err := Parse([]byte("logging:\n  file_mode: \"0644\"\n")); err != nil {
		t.Fatalf("0644 should be allowed with a warning: %v", err)
	} else if len(warns) == 0 {
		t.Error("expected a warning about world-readable logs")
	}
}

func TestDNSServerPortNormalisation(t *testing.T) {
	cfg, _, err := Parse([]byte("dns:\n  servers: [\"192.0.2.1\", \"192.0.2.2:5353\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Servers[0] != "192.0.2.1:53" || cfg.DNS.Servers[1] != "192.0.2.2:5353" {
		t.Errorf("unexpected normalisation: %v", cfg.DNS.Servers)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	res, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("a missing configuration file must not be fatal: %v", err)
	}
	if !res.Created || res.Config.Monitoring.HealthInterval.D() != 15*time.Second {
		t.Errorf("expected defaults, got %+v", res.Config.Monitoring)
	}
}

func TestWriteDefaultAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ipulse.yaml")
	created, err := WriteDefault(path)
	if err != nil || !created {
		t.Fatalf("WriteDefault: %v created=%v", err, created)
	}
	again, err := WriteDefault(path)
	if err != nil || again {
		t.Fatalf("WriteDefault must not overwrite: %v created=%v", err, again)
	}
	res, err := Load(path)
	if err != nil {
		t.Fatalf("round-trip load failed: %v", err)
	}
	if res.Config.Dashboard.Port != 8750 {
		t.Errorf("unexpected port after round trip: %d", res.Config.Dashboard.Port)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("configuration file should not be world-accessible, got %o", perm)
	}
}

func TestRedactedHidesToken(t *testing.T) {
	cfg := Default()
	cfg.Dashboard.AuthToken = "supersecrettoken1234"
	if cfg.Redacted().Dashboard.AuthToken == cfg.Dashboard.AuthToken {
		t.Error("auth token must be redacted")
	}
	if cfg.Dashboard.AuthToken != "supersecrettoken1234" {
		t.Error("Redacted must not mutate the original")
	}
}

func TestPortablePaths(t *testing.T) {
	t.Setenv(EnvHome, filepath.Join(t.TempDir(), "portable"))
	if !strings.Contains(DefaultConfigPath(), "portable") {
		t.Errorf("portable mode should redirect the config path: %s", DefaultConfigPath())
	}
	if !strings.Contains(DefaultDataDir(), "portable") {
		t.Errorf("portable mode should redirect the data dir: %s", DefaultDataDir())
	}
}

func containsHost(list []string, want string) bool {
	for _, h := range list {
		if h == want {
			return true
		}
	}
	return false
}
