package routing

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestPathHopCountAndSignature(t *testing.T) {
	p := Path{
		Destination: "1.1.1.1",
		Hops: []Hop{
			{TTL: 1, Addr: "192.168.1.1", RTT: 3 * time.Millisecond},
			{TTL: 2, Timeout: true},
			{TTL: 3, Addr: "198.51.100.20", RTT: 9 * time.Millisecond},
			{TTL: 4, Addr: "1.1.1.1", RTT: 8 * time.Millisecond, Destination: true},
		},
		Complete: true,
	}
	if p.HopCount() != 4 {
		t.Errorf("HopCount = %d, want 4", p.HopCount())
	}
	if got := p.Signature(); got != "192.168.1.1 * 198.51.100.20 1.1.1.1" {
		t.Errorf("Signature = %q", got)
	}
	if addrs := p.Addresses(); len(addrs) != 3 {
		t.Errorf("Addresses = %v", addrs)
	}
}

func TestHopCountWhenDestinationNotReached(t *testing.T) {
	p := Path{Hops: []Hop{{TTL: 1, Addr: "192.168.1.1"}, {TTL: 2, Timeout: true}, {TTL: 3, Timeout: true}}}
	if p.HopCount() != 3 {
		t.Errorf("HopCount = %d, want the number probed", p.HopCount())
	}
}

// TestCompareIgnoresSilentHops is the property that stops rate-limited routers from
// producing a route-change event on every measurement.
func TestCompareIgnoresSilentHops(t *testing.T) {
	before := Path{Hops: []Hop{
		{TTL: 1, Addr: "192.168.1.1"},
		{TTL: 2, Addr: "10.1.1.1"},
		{TTL: 3, Addr: "1.1.1.1", Destination: true},
	}}
	// The middle hop simply stopped answering, which is not a route change.
	after := Path{Hops: []Hop{
		{TTL: 1, Addr: "192.168.1.1"},
		{TTL: 2, Timeout: true},
		{TTL: 3, Addr: "1.1.1.1", Destination: true},
	}}
	if d := Compare(before, after, 0); d.Changed {
		t.Errorf("a hop that stopped answering must not count as a change: %+v", d)
	}
}

func TestCompareDetectsRealChange(t *testing.T) {
	before := Path{Hops: []Hop{
		{TTL: 1, Addr: "192.168.1.1"},
		{TTL: 2, Addr: "10.1.1.1"},
		{TTL: 3, Addr: "10.2.2.2"},
		{TTL: 4, Addr: "1.1.1.1", Destination: true},
	}}
	after := Path{Hops: []Hop{
		{TTL: 1, Addr: "192.168.1.1"},
		{TTL: 2, Addr: "10.9.9.9"},
		{TTL: 3, Addr: "10.8.8.8"},
		{TTL: 4, Addr: "1.1.1.1", Destination: true},
	}}
	d := Compare(before, after, 1)
	if !d.Changed {
		t.Fatalf("two changed hops should exceed a tolerance of one: %+v", d)
	}
	if d.ChangedHops != 2 {
		t.Errorf("ChangedHops = %d, want 2", d.ChangedHops)
	}
	if d.FirstChange != 2 {
		t.Errorf("FirstChange = %d, want 2", d.FirstChange)
	}

	// A single differing hop is within tolerance, which is what ECMP produces.
	after.Hops[2].Addr = "10.2.2.2"
	if d := Compare(before, after, 1); d.Changed {
		t.Errorf("one differing hop should be tolerated: %+v", d)
	}
}

func TestCompareHopCountDelta(t *testing.T) {
	before := Path{Hops: []Hop{{TTL: 1, Addr: "a"}, {TTL: 2, Addr: "b", Destination: true}}}
	after := Path{Hops: []Hop{{TTL: 1, Addr: "a"}, {TTL: 2, Addr: "b"}, {TTL: 3, Addr: "c", Destination: true}}}
	if d := Compare(before, after, 0); d.HopCountDelta != 1 {
		t.Errorf("HopCountDelta = %d, want 1", d.HopCountDelta)
	}
}

func TestBuildEchoChecksum(t *testing.T) {
	msg := buildEcho(false, 0x1234, 0x5678)
	if msg[0] != icmpv4Echo || msg[1] != 0 {
		t.Errorf("header = %v", msg[:2])
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 0x1234 {
		t.Errorf("id = %x", got)
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 0x5678 {
		t.Errorf("seq = %x", got)
	}
	// A correct checksum makes the whole message sum to zero.
	if sum := checksum(msg); sum != 0 {
		t.Errorf("verification checksum = %x, want 0", sum)
	}

	// IPv6 leaves the checksum to the kernel, which computes it over a pseudo-header.
	msg6 := buildEcho(true, 1, 2)
	if msg6[0] != icmpv6EchoRequest {
		t.Errorf("IPv6 type = %d", msg6[0])
	}
	if binary.BigEndian.Uint16(msg6[2:4]) != 0 {
		t.Error("the IPv6 checksum must be left for the kernel")
	}
}

func TestParseICMPEchoReply(t *testing.T) {
	reply := buildEcho(false, 1, 4242)
	reply[0] = icmpv4EchoReply
	kind, seq := parseICMP(reply, false, false)
	if kind != replyEcho || seq != 4242 {
		t.Errorf("kind = %v seq = %d", kind, seq)
	}
	if kind, _ := parseICMP([]byte{1, 2}, false, false); kind != replyNone {
		t.Error("a truncated message must not be classified")
	}
}

// TestParseICMPTimeExceeded checks the embedded-datagram parsing that ties an error
// message back to the probe that caused it.
func TestParseICMPTimeExceeded(t *testing.T) {
	// ICMP time exceeded: header, unused word, then the original IP header and the
	// first eight bytes of the original datagram.
	original := buildEcho(false, 1, 777)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // version 4, header length 5 words

	msg := make([]byte, 0, 8+len(ipHeader)+8)
	msg = append(msg, icmpv4TimeExceeded, 0, 0, 0, 0, 0, 0, 0)
	msg = append(msg, ipHeader...)
	msg = append(msg, original[:8]...)

	kind, seq := parseICMP(msg, false, false)
	if kind != replyTimeExceeded {
		t.Errorf("kind = %v, want time exceeded", kind)
	}
	if seq != 777 {
		t.Errorf("seq = %d, want 777", seq)
	}
}

func TestSequenceNumbersAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 100; i++ {
		s := nextSeq()
		if seen[s] {
			t.Fatalf("duplicate sequence %d", s)
		}
		seen[s] = true
	}
}

func TestTracerDefaults(t *testing.T) {
	tr := New(Config{})
	if tr.cfg.MaxHops != 20 || tr.cfg.ProbesPerHop != 1 || tr.cfg.Timeout != 2*time.Second {
		t.Errorf("defaults not applied: %+v", tr.cfg)
	}
	// An absurd hop count is clamped rather than accepted.
	if got := New(Config{MaxHops: 500}).cfg.MaxHops; got != 20 {
		t.Errorf("MaxHops = %d, want the default when out of range", got)
	}
}

func TestTraceRejectsBadDestination(t *testing.T) {
	tr := New(Config{MaxHops: 3, Timeout: 200 * time.Millisecond, TotalTimeout: time.Second})
	if _, err := tr.Trace(context.Background(), "invalid..host"); err == nil {
		t.Error("expected an error for an unresolvable destination")
	}
}

// TestLivePathMeasurement exercises the real thing when ICMP is permitted.
func TestLivePathMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("live network test")
	}
	tr := New(Config{MaxHops: 12, ProbesPerHop: 1, Timeout: time.Second, TotalTimeout: 20 * time.Second})
	ok, err := tr.Available()
	if !ok {
		t.Skipf("ICMP unavailable: %v", err)
	}
	path, err := tr.Trace(context.Background(), "1.1.1.1")
	if err != nil {
		t.Skipf("trace failed, probably no Internet: %v", err)
	}
	if len(path.Hops) == 0 {
		t.Fatal("no hops recorded")
	}
	if !path.Complete {
		t.Logf("destination not reached within %d hops", len(path.Hops))
	}
	responded := 0
	for _, h := range path.Hops {
		if h.Addr != "" {
			responded++
			if h.RTT <= 0 {
				t.Errorf("hop %d answered with no round trip", h.TTL)
			}
		}
	}
	t.Logf("%d of %d hops answered; signature %s", responded, len(path.Hops), path.Signature())
	if responded == 0 {
		t.Error("no hop answered at all")
	}
}
