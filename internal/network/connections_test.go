package network

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/util"
)

// fakeProvider returns a scripted socket table, so the collector's behaviour can be
// tested exactly rather than against whatever the host happens to be doing.
type fakeProvider struct {
	conns []platform.Connection
	err   error
	opts  platform.ConnOptions
}

func (f *fakeProvider) Name() string                              { return "fake" }
func (f *fakeProvider) Capabilities() platform.Capabilities       { return platform.Capabilities{} }
func (f *fakeProvider) Interfaces() ([]platform.Interface, error) { return nil, nil }
func (f *fakeProvider) Routes() ([]platform.Route, error)         { return nil, nil }
func (f *fakeProvider) Wireless() ([]platform.WirelessLink, error) {
	return nil, platform.ErrUnsupported
}
func (f *fakeProvider) DNSServers() ([]netip.AddrPort, error) { return nil, nil }
func (f *fakeProvider) ProcessInfo(int) (platform.Process, error) {
	return platform.Process{}, platform.ErrNotFound
}
func (f *fakeProvider) Connections(opts platform.ConnOptions) ([]platform.Connection, error) {
	f.opts = opts
	return f.conns, f.err
}

func conn(proto, local, remote, state string, pid int, process string) platform.Connection {
	c := platform.Connection{
		Protocol: proto,
		Local:    netip.MustParseAddrPort(local),
		State:    state,
		PID:      pid,
		Process:  process,
		Exe:      "/usr/bin/" + process,
		User:     "alice",
	}
	if remote != "" {
		c.Remote = netip.MustParseAddrPort(remote)
	}
	return c
}

func defaultConfig() Config {
	return Config{
		IncludeUDP: true, ResolveProcess: true, Max: 100,
		Privacy: Privacy{
			CollectProcessNames: true, CollectExecutablePaths: true, CollectUsernames: true,
		},
	}
}

func TestCollectClassifiesInternalAndExternal(t *testing.T) {
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
		conn("tcp", "192.168.1.20:44101", "192.168.1.50:445", platform.StateEstablished, 901, "smbclient"),
		conn("udp", "192.168.1.20:51000", "8.8.8.8:53", platform.StateNone, 902, "systemd-resolve"),
		conn("tcp", "192.168.1.20:44102", "10.0.0.5:22", platform.StateSynSent, 903, "ssh"),
	}}
	c := NewCollector(defaultConfig(), p)

	snap, err := c.Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Total != 4 {
		t.Fatalf("total = %d, want 4", snap.Total)
	}
	if snap.External != 2 {
		t.Errorf("external = %d, want 2", snap.External)
	}
	if snap.Internal != 2 {
		t.Errorf("internal = %d, want 2", snap.Internal)
	}
	if snap.TCP != 3 || snap.UDP != 1 {
		t.Errorf("protocol counts: tcp=%d udp=%d", snap.TCP, snap.UDP)
	}
	if snap.Failed != 1 {
		t.Errorf("failed = %d, want 1 (the SYN_SENT ssh attempt)", snap.Failed)
	}
	if snap.WithProcess != 4 {
		t.Errorf("attributed = %d, want 4", snap.WithProcess)
	}
	if got := DistinctExternalDestinations(snap); got != 2 {
		t.Errorf("distinct external destinations = %d, want 2", got)
	}
}

func TestExtraInternalRangesAreHonoured(t *testing.T) {
	ranges, _ := util.ParsePrefixes([]string{"198.51.100.0/24"})
	cfg := defaultConfig()
	cfg.InternalRanges = ranges

	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "198.51.100.9:443", platform.StateEstablished, 900, "curl"),
	}}
	snap, err := NewCollector(cfg, p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Internal != 1 || snap.External != 0 {
		t.Errorf("a configured extra range must count as internal: %+v", snap)
	}
	if !snap.Connections[0].Internal {
		t.Error("the record must be flagged internal")
	}
}

// TestDurationAccumulates is why the collector keeps first-seen state: neither platform
// reports how long a socket has existed.
func TestDurationAccumulates(t *testing.T) {
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
	}}
	c := NewCollector(defaultConfig(), p)
	start := time.Now()

	first, _ := c.Collect(start)
	if first.Connections[0].Duration != 0 {
		t.Errorf("first observation duration = %v, want 0", first.Connections[0].Duration)
	}
	later, _ := c.Collect(start.Add(90 * time.Second))
	if later.Connections[0].Duration != 90*time.Second {
		t.Errorf("duration = %v, want 90s", later.Connections[0].Duration)
	}
	if !later.Connections[0].FirstSeen.Equal(start) {
		t.Errorf("first seen = %v, want %v", later.Connections[0].FirstSeen, start)
	}
}

func TestClosedConnectionsAreForgotten(t *testing.T) {
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
	}}
	c := NewCollector(defaultConfig(), p)
	start := time.Now()
	c.Collect(start)

	p.conns = nil
	c.Collect(start.Add(time.Minute))
	if len(c.firstSeen) != 0 {
		t.Errorf("expected closed connections to be forgotten, tracking %d", len(c.firstSeen))
	}
}

func TestPrivacySwitchesSuppressFields(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy = Privacy{} // everything off
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
	}}
	snap, err := NewCollector(cfg, p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := snap.Connections[0]
	if got.Process != "" || got.Exe != "" || got.User != "" || got.PID != 0 {
		t.Errorf("privacy settings did not suppress identity fields: %+v", got)
	}
	// The connection itself is still recorded: the metadata that matters for
	// observability is the endpoints.
	if got.RemoteIP != "203.0.113.7" {
		t.Errorf("remote address should still be recorded: %+v", got)
	}
}

func TestAnonymiseLocalAddresses(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.AnonymizeLocal = true
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:44100", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
		conn("tcp", "[2001:db8::5]:44101", "[2606:4700::1]:443", platform.StateEstablished, 901, "curl"),
	}}
	snap, err := NewCollector(cfg, p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Connections[0].LocalIP != "192.168.1.0/24" {
		t.Errorf("IPv4 local address = %q, want a masked prefix", snap.Connections[0].LocalIP)
	}
	if snap.Connections[1].LocalIP != "2001:db8::/64" {
		t.Errorf("IPv6 local address = %q, want a masked prefix", snap.Connections[1].LocalIP)
	}
}

func TestIgnoreRules(t *testing.T) {
	ignoreDest, _ := util.ParsePrefixes([]string{"203.0.113.0/24"})
	cfg := defaultConfig()
	cfg.IgnoreProcesses = []string{"backup*"}
	cfg.IgnoreDestinations = ignoreDest

	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:1", "203.0.113.7:443", platform.StateEstablished, 900, "curl"),
		conn("tcp", "192.168.1.20:2", "8.8.8.8:443", platform.StateEstablished, 901, "backup-agent"),
		conn("tcp", "192.168.1.20:3", "1.1.1.1:443", platform.StateEstablished, 902, "curl"),
	}}
	snap, err := NewCollector(cfg, p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Total != 1 || snap.Skipped != 2 {
		t.Errorf("ignore rules wrong: total=%d skipped=%d", snap.Total, snap.Skipped)
	}
	if snap.Connections[0].RemoteIP != "1.1.1.1" {
		t.Errorf("wrong connection survived: %+v", snap.Connections[0])
	}
}

func TestCollectorPassesOptionsThrough(t *testing.T) {
	cfg := defaultConfig()
	cfg.IncludeUDP = false
	cfg.IncludeListening = true
	cfg.IncludeLoopback = true
	cfg.Max = 42
	p := &fakeProvider{}
	if _, err := NewCollector(cfg, p).Collect(time.Now()); err != nil {
		t.Fatal(err)
	}
	if p.opts.UDP || !p.opts.IncludeListening || !p.opts.IncludeLoopback || p.opts.Max != 42 {
		t.Errorf("options not passed through: %+v", p.opts)
	}
}

func TestCollectPropagatesErrors(t *testing.T) {
	p := &fakeProvider{err: platform.ErrPermission}
	if _, err := NewCollector(defaultConfig(), p).Collect(time.Now()); err == nil {
		t.Error("expected the platform error to propagate")
	}
}

func TestSummariseByProcess(t *testing.T) {
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:1", "203.0.113.7:443", platform.StateEstablished, 900, "chrome"),
		conn("tcp", "192.168.1.20:2", "203.0.113.8:443", platform.StateEstablished, 900, "chrome"),
		conn("tcp", "192.168.1.20:3", "10.0.0.5:22", platform.StateSynSent, 901, "scanner"),
		conn("tcp", "192.168.1.20:4", "10.0.0.6:22", platform.StateSynSent, 901, "scanner"),
		conn("tcp", "192.168.1.20:5", "10.0.0.7:22", platform.StateSynSent, 901, "scanner"),
	}}
	snap, err := NewCollector(defaultConfig(), p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	summaries := SummariseByProcess(snap)
	if len(summaries) != 2 {
		t.Fatalf("got %d summaries", len(summaries))
	}
	if summaries[0].Process != "scanner" || summaries[0].Connections != 3 {
		t.Errorf("expected scanner first with 3 connections: %+v", summaries[0])
	}
	if summaries[0].Failed != 3 || summaries[0].Internal != 3 {
		t.Errorf("scanner summary wrong: %+v", summaries[0])
	}
	if len(summaries[1].Destinations) != 2 {
		t.Errorf("chrome should have 2 distinct destinations: %+v", summaries[1])
	}
	if TopProcess(snap) != "scanner" {
		t.Errorf("TopProcess = %q", TopProcess(snap))
	}
}

func TestUnattributedConnectionsAreGrouped(t *testing.T) {
	p := &fakeProvider{conns: []platform.Connection{
		conn("tcp", "192.168.1.20:1", "203.0.113.7:443", platform.StateEstablished, 0, ""),
	}}
	snap, err := NewCollector(defaultConfig(), p).Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snap.WithProcess != 0 {
		t.Error("an unattributed connection must not count as attributed")
	}
	summaries := SummariseByProcess(snap)
	if len(summaries) != 1 || summaries[0].Process != "(unattributed)" {
		t.Errorf("summaries = %+v", summaries)
	}
	// With nothing attributable, TopProcess falls back rather than inventing a name.
	if TopProcess(snap) != "(unattributed)" {
		t.Errorf("TopProcess = %q", TopProcess(snap))
	}
}

func TestEndpointKey(t *testing.T) {
	if got := EndpointKey("203.0.113.7", 443, "TCP"); got != "tcp|203.0.113.7|443" {
		t.Errorf("EndpointKey = %q", got)
	}
}

func TestLiveCollectorRuns(t *testing.T) {
	c := NewCollector(defaultConfig(), platform.New())
	snap, err := c.Collect(time.Now())
	if err != nil {
		t.Skipf("connection collection unavailable on this host: %v", err)
	}
	t.Logf("collected %d connections (%d external, %d internal, %d attributed)",
		snap.Total, snap.External, snap.Internal, snap.WithProcess)
	for _, conn := range snap.Connections {
		if conn.Protocol == "" || conn.Key == "" {
			t.Errorf("malformed record: %+v", conn)
		}
	}
	_ = context.Background()
}
