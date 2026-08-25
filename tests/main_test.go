// Package tests holds iPulse's cross-cutting integration tests: the ones that exercise
// several packages together rather than one in isolation.
//
// Unit tests live beside the code they test. These start a real agent, a real database
// and a real HTTP server, and check that the pieces fit.
//
// None of them requires the Internet, and none requires a real outage. Where a network
// target is needed, the test starts a local listener and points the configuration at it,
// so the suite behaves the same on a laptop, in CI and on a disconnected machine.
package tests

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/config"
)

// repoRoot is the module root, resolved from this file's location so the packaging
// tests can read the manifests regardless of the working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine the test file location")
	}
	return filepath.Dir(filepath.Dir(file))
}

// localListener starts a TCP listener on loopback and returns its address. It stands in
// for an external probe target: a connection to it succeeds, which is all the
// connectivity and latency probes need, and it cannot reach the Internet.
func localListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// deadListener returns an address that nothing is listening on. Binding and immediately
// closing guarantees the port is free, which is how a connection failure is produced
// without waiting for a timeout to a routable address.
func deadListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// offlineConfig returns a configuration that exercises the agent without touching the
// Internet: local probe targets, every outbound collector disabled, short intervals.
func offlineConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	target := localListener(t)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split %q: %v", target, err)
	}
	port, _ := strconv.Atoi(portStr)

	cfg := config.Default()
	cfg.Service.DataDir = filepath.Join(dir, "data")
	cfg.Service.LogDir = filepath.Join(dir, "logs")
	cfg.Service.HostnameOverride = "test-host"
	cfg.Service.ShutdownTimeout = config.Duration(5 * time.Second)
	cfg.Database.Path = filepath.Join(dir, "data", "ipulse.db")

	// Local targets only.
	cfg.Connectivity.Targets = []config.Target{
		{Name: "local", Type: "tcp", Address: target, Notes: "test listener"},
	}
	cfg.Connectivity.RequiredSuccess = 1
	cfg.Connectivity.IPLiterals = []string{host}
	cfg.Connectivity.HTTPSTargets = nil
	cfg.Connectivity.GatewayProbeMethod = "tcp"

	cfg.Latency.Targets = []string{host}
	cfg.Latency.Method = "tcp"
	cfg.Latency.TCPPort = port
	cfg.Latency.Probes = 3
	cfg.Latency.Spacing = config.Duration(5 * time.Millisecond)
	cfg.Latency.Timeout = config.Duration(time.Second)
	cfg.Latency.IncludeGateway = false

	// "localhost" resolves from the hosts file, so DNS timing is measured without a
	// query leaving the machine.
	cfg.DNS.Names = []string{"localhost"}
	cfg.DNS.Servers = nil
	cfg.DNS.UseSystemResolver = true
	cfg.DNS.Timeout = config.Duration(time.Second)

	// Everything that would reach the Internet is off.
	cfg.SpeedTest.Enabled = false
	cfg.PublicIP.Enabled = false
	cfg.Routing.Enabled = false
	cfg.ThreatIntel.Enabled = false
	cfg.Destinations.ReverseDNS = false

	// The shortest intervals validation permits. Most collectors also run on start,
	// so a test rarely waits a whole interval.
	cfg.Monitoring.HealthInterval = config.Duration(time.Second)
	cfg.Monitoring.DNSInterval = config.Duration(time.Second)
	cfg.Monitoring.LatencyInterval = config.Duration(time.Second)
	cfg.Monitoring.InterfaceInterval = config.Duration(time.Second)
	cfg.Monitoring.TrafficInterval = config.Duration(time.Second)
	cfg.Monitoring.ConnectionInterval = config.Duration(time.Second)
	cfg.Monitoring.HealthScoreInterval = config.Duration(10 * time.Second)
	cfg.Monitoring.Jitter = 0
	cfg.Monitoring.ProbeTimeout = config.Duration(2 * time.Second)

	cfg.Logging.Console = false
	cfg.Logging.Syslog = false
	cfg.Logging.EventLog = false
	cfg.Logging.Level = "debug"

	cfg.Dashboard.Enabled = false
	cfg.Dashboard.Port = 0

	cfg.Normalize()
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("the offline test configuration is invalid: %v", err)
	}
	return &cfg
}

// startAgent builds and runs an agent, returning it with a stop function.
func startAgent(t *testing.T, cfg *config.Config) (*agent.Agent, func()) {
	t.Helper()
	a, err := agent.New(agent.Options{Config: cfg, Mode: "foreground"})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	return runAgent(t, a)
}

// runAgent starts an already-built agent. Run is given a ready callback so callers wait
// for actual readiness rather than sleeping, and stop is idempotent so a test may call
// it explicitly and still rely on the cleanup.
func runAgent(t *testing.T, a *agent.Agent) (*agent.Agent, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, func() { close(ready) }) }()

	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("the agent exited before reporting ready: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("the agent did not report ready within 30s")
	}

	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Errorf("agent run returned: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("the agent did not shut down within 30s")
		}
	}
	t.Cleanup(stop)
	return a, stop
}

// freePort reserves a loopback port and releases it, so a server can bind it without
// two parallel tests choosing the same number.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// eventually polls until cond is true, failing with msg on timeout. Polling keeps the
// tests free of fixed sleeps, so they are neither slow nor flaky.
func eventually(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, msg)
}

// mustReadFile fails the test rather than returning an error, which keeps the packaging
// assertions readable.
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// newHTTPClient returns a client that never follows redirects, so a test can assert on
// the status code the handler actually returned.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
