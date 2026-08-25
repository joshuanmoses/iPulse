package latency

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpNetworks lists, in preference order, the socket types used for echo requests.
//
// "udp4"/"udp6" are unprivileged datagram ping sockets: on Linux they work when the
// process group is inside net.ipv4.ping_group_range, and they need no capability at
// all. The raw variants need CAP_NET_RAW (Linux) or Administrator (Windows).
var icmpNetworks = []struct {
	network string
	address string
	v6      bool
	raw     bool
}{
	{"udp4", "0.0.0.0", false, false},
	{"ip4:icmp", "0.0.0.0", false, true},
}

var icmpNetworks6 = []struct {
	network string
	address string
	v6      bool
	raw     bool
}{
	{"udp6", "::", true, false},
	{"ip6:ipv6-icmp", "::", true, true},
}

// probeICMPSupport reports whether an ICMP socket can be opened at all.
func probeICMPSupport() (bool, error) {
	var lastErr error
	for _, n := range icmpNetworks {
		c, err := icmp.ListenPacket(n.network, n.address)
		if err == nil {
			_ = c.Close()
			return true, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no ICMP socket type available")
	}
	return false, lastErr
}

// echoID is this process's ICMP identifier. On datagram sockets the kernel rewrites it,
// so replies are matched on sequence number instead; on raw sockets it is what separates
// our replies from another process's.
var echoID = os.Getpid() & 0xffff

// seqCounter keeps sequence numbers unique across concurrent probes in one process.
var seqCounter struct {
	sync.Mutex
	n int
}

func nextSeq() int {
	seqCounter.Lock()
	defer seqCounter.Unlock()
	seqCounter.n = (seqCounter.n + 1) & 0xffff
	return seqCounter.n
}

// probeICMP sends the configured number of echo requests and times the replies.
func (p *Prober) probeICMP(ctx context.Context, target string) Result {
	res := Result{Target: target, Method: MethodICMP}

	ip, err := resolveTarget(ctx, target)
	if err != nil {
		res.Err = fmt.Errorf("resolve %s: %w", target, err)
		summarise(&res)
		return res
	}
	res.Resolved = ip.String()
	v6 := ip.To4() == nil

	conn, raw, err := listenICMP(v6)
	if err != nil {
		res.Err = err
		summarise(&res)
		return res
	}
	defer conn.Close()

	var dst net.Addr = &net.UDPAddr{IP: ip}
	if raw {
		dst = &net.IPAddr{IP: ip}
	}

	msgType := icmp.Type(ipv4.ICMPTypeEcho)
	if v6 {
		msgType = ipv6.ICMPTypeEchoRequest
	}

	buf := make([]byte, 1500)
	for i := 0; i < p.cfg.Probes; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 0 {
			select {
			case <-time.After(p.cfg.Spacing):
			case <-ctx.Done():
				return finish(&res)
			}
		}

		seq := nextSeq()
		// A payload carrying the send time is unnecessary because the RTT is measured
		// locally, but a fixed, recognisable payload makes captures easy to read and
		// keeps the packet a realistic size.
		body := &icmp.Echo{ID: echoID, Seq: seq, Data: []byte("iPulse-latency-probe")}
		msg := icmp.Message{Type: msgType, Code: 0, Body: body}
		wire, err := msg.Marshal(nil)
		if err != nil {
			res.Err = err
			continue
		}

		res.Sent++
		deadline := time.Now().Add(p.cfg.Timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)

		start := time.Now()
		if _, err := conn.WriteTo(wire, dst); err != nil {
			res.Err = fmt.Errorf("send: %w", err)
			continue
		}

		// Read until our reply arrives or the deadline passes: the socket also receives
		// replies to other processes' pings on raw sockets, and unrelated ICMP traffic.
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				if !isTimeout(err) {
					res.Err = err
				}
				break
			}
			rtt := time.Since(start)
			ok, echoErr := matchEcho(buf[:n], peer, ip, seq, v6, raw)
			if echoErr != nil {
				res.Err = echoErr
				break
			}
			if !ok {
				continue // someone else's reply, or an unrelated ICMP message
			}
			res.RTTs = append(res.RTTs, rtt)
			res.Recv++
			break
		}
	}
	return finish(&res)
}

func finish(res *Result) Result {
	summarise(res)
	// A result with successful probes is a success even if an individual probe errored.
	if res.Recv > 0 {
		res.Err = nil
		res.Error = ""
		return *res
	}
	// Total loss with no specific error means every probe timed out; say so explicitly
	// rather than returning a silent zero result.
	if res.Err == nil && res.Sent > 0 {
		res.Err = fmt.Errorf("no response from %s after %d %s probes", res.Target, res.Sent, res.Method)
		res.Error = res.Err.Error()
	}
	return *res
}

func listenICMP(v6 bool) (*icmp.PacketConn, bool, error) {
	list := icmpNetworks
	if v6 {
		list = icmpNetworks6
	}
	var lastErr error
	for _, n := range list {
		c, err := icmp.ListenPacket(n.network, n.address)
		if err == nil {
			return c, n.raw, nil
		}
		lastErr = err
	}
	return nil, false, fmt.Errorf("open icmp socket: %w", lastErr)
}

// matchEcho reports whether a received message is the echo reply we are waiting for.
// It also recognises the ICMP error messages that indicate a hard failure, so an
// unreachable destination is reported as such instead of as a timeout.
func matchEcho(b []byte, peer net.Addr, want net.IP, seq int, v6, raw bool) (bool, error) {
	proto := ipv4.ICMPTypeEchoReply.Protocol()
	if v6 {
		proto = ipv6.ICMPTypeEchoReply.Protocol()
	}
	msg, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return false, nil
	}

	// The reply must come from the address we probed; anything else belongs to another
	// conversation (or is an error message from an intermediate hop).
	peerIP := addrIP(peer)

	switch body := msg.Body.(type) {
	case *icmp.Echo:
		if msg.Type != ipv4.ICMPTypeEchoReply && msg.Type != ipv6.ICMPTypeEchoReply {
			return false, nil
		}
		if peerIP != nil && want != nil && !peerIP.Equal(want) {
			return false, nil
		}
		if body.Seq != seq {
			return false, nil
		}
		// On raw sockets the identifier is ours; on datagram sockets the kernel
		// replaces it, so it cannot be checked.
		if raw && body.ID != echoID {
			return false, nil
		}
		return true, nil
	case *icmp.DstUnreach:
		return false, fmt.Errorf("destination unreachable from %s", peerIP)
	case *icmp.TimeExceeded:
		return false, fmt.Errorf("time exceeded from %s", peerIP)
	}
	return false, nil
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}
