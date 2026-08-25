package dnsmon

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNormalizeServer(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":            "1.1.1.1:53",
		"1.1.1.1:5353":       "1.1.1.1:5353",
		"2606:4700:4700::11": "[2606:4700:4700::11]:53",
		"resolver.example":   "resolver.example:53",
		" 8.8.8.8 ":          "8.8.8.8:53",
	}
	for in, want := range cases {
		if got := normalizeServer(in); got != want {
			t.Errorf("normalizeServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeSetSummary(t *testing.T) {
	set := ProbeSet{Results: []Result{
		{Server: "system", OK: true, Duration: 5 * time.Millisecond},
		{Server: "1.1.1.1:53", OK: true, Duration: 15 * time.Millisecond},
		{Server: "192.0.2.1:53", OK: false, Error: "timeout", Duration: 3 * time.Second},
	}}
	summarise(&set)

	if set.Tested != 3 || set.Failed != 1 {
		t.Errorf("counts wrong: %+v", set)
	}
	if set.Fastest != 5*time.Millisecond || set.Slowest != 15*time.Millisecond {
		t.Errorf("range should ignore failures: %v-%v", set.Fastest, set.Slowest)
	}
	if set.Average != 10*time.Millisecond {
		t.Errorf("average = %v, want 10ms", set.Average)
	}
	if !set.AnyOK || set.AllFailed {
		t.Errorf("flags wrong: %+v", set)
	}
	if got := set.FailedServers(); len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Errorf("failed servers = %v", got)
	}
	if got := set.WorkingServers(); len(got) != 2 {
		t.Errorf("working servers = %v", got)
	}
	if set.Describe() != "2/3 answered" {
		t.Errorf("describe = %q", set.Describe())
	}
}

func TestProbeSetAllFailed(t *testing.T) {
	set := ProbeSet{Results: []Result{
		{Server: "192.0.2.1:53", OK: false},
		{Server: "192.0.2.2:53", OK: false},
	}}
	summarise(&set)
	if !set.AllFailed || set.AnyOK {
		t.Errorf("expected all-failed: %+v", set)
	}
	if set.Average != 0 {
		t.Errorf("average with no successes should be 0, got %v", set.Average)
	}
}

// TestResolveViaUnreachableServer exercises the failure path deterministically: a
// resolver address that nothing listens on must fail fast and be reported, not hang.
func TestResolveViaUnreachableServer(t *testing.T) {
	// Bind a UDP socket and close it, so the port is almost certainly unused.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	p := New(Config{Timeout: 500 * time.Millisecond})
	start := time.Now()
	res := p.ResolveVia(context.Background(), "example.invalid", addr)
	elapsed := time.Since(start)

	if res.OK {
		t.Errorf("expected failure against a dead resolver: %+v", res)
	}
	if res.Error == "" {
		t.Error("expected an error message")
	}
	if elapsed > 3*time.Second {
		t.Errorf("failure took %v; the timeout should bound it", elapsed)
	}
	if res.Server != addr {
		t.Errorf("server = %q, want %q", res.Server, addr)
	}
}

// TestResolveAgainstLocalServer runs a real query against a minimal DNS responder, so
// the timing path is covered without depending on the Internet.
func TestResolveAgainstLocalServer(t *testing.T) {
	server, addr, stop := startStubDNS(t)
	defer stop()
	_ = server

	p := New(Config{Timeout: 2 * time.Second})
	res := p.ResolveVia(context.Background(), "test.invalid", addr)
	if !res.OK {
		t.Fatalf("stub resolver query failed: %+v", res)
	}
	if len(res.Answers) != 1 || res.Answers[0] != "192.0.2.77" {
		t.Errorf("answers = %v, want [192.0.2.77]", res.Answers)
	}
	if res.Duration <= 0 {
		t.Error("expected a positive duration")
	}
	if res.MS() <= 0 {
		t.Error("expected a positive millisecond value")
	}
}

func TestProbeUsesSystemAndServers(t *testing.T) {
	_, addr, stop := startStubDNS(t)
	defer stop()

	// UseSystem false keeps the test independent of the host's resolver.
	p := New(Config{Timeout: time.Second, UseSystem: false})
	set := p.Probe(context.Background(), "test.invalid", []string{addr})
	if set.Tested != 1 || !set.AnyOK {
		t.Errorf("unexpected probe set: %+v", set)
	}
}

// startStubDNS runs a minimal UDP DNS server that answers every A query with
// 192.0.2.77. Hand-assembling the response keeps the test dependency-free.
func startStubDNS(t *testing.T) (net.PacketConn, string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildStubResponse(buf[:n])
			if resp != nil {
				_, _ = conn.WriteTo(resp, peer)
			}
		}
	}()
	return conn, conn.LocalAddr().String(), func() {
		_ = conn.Close()
		<-done
	}
}

// buildStubResponse echoes the query and appends one A record.
func buildStubResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	// Find the end of the question section: labels terminated by a zero byte, then
	// QTYPE and QCLASS.
	i := 12
	for i < len(query) && query[i] != 0 {
		length := int(query[i])
		i += length + 1
	}
	if i+5 > len(query) {
		return nil
	}
	questionEnd := i + 5
	qtype := int(query[i+1])<<8 | int(query[i+2])

	resp := make([]byte, 0, questionEnd+16)
	resp = append(resp, query[:questionEnd]...)
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x80 // RA=1, RCODE=0
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0

	// Only A queries get an answer; AAAA gets NOERROR with no records, which the Go
	// resolver handles by using the A answer.
	if qtype == 1 {
		resp[6], resp[7] = 0, 1 // ANCOUNT = 1
		resp = append(resp,
			0xc0, 0x0c, // name: pointer to the question
			0x00, 0x01, // type A
			0x00, 0x01, // class IN
			0x00, 0x00, 0x00, 0x3c, // TTL 60
			0x00, 0x04, // RDLENGTH
			192, 0, 2, 77,
		)
	}
	return resp
}
