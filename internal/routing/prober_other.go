//go:build !linux

package routing

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// The portable prober uses a raw ICMP socket, which is what Windows requires for path
// measurement: there is no unprivileged equivalent of the Linux ping socket, and the
// "time exceeded" replies from intermediate routers are only visible to a raw socket.
// Running the service as Administrator (the installer's default, because the extended
// socket tables need it too) is therefore what enables this feature on Windows.
type portableProber struct {
	conn *icmp.PacketConn
	v6   bool
	raw  bool
}

func newProber(v6 bool) (prober, error) {
	type candidate struct {
		network, address string
		raw              bool
	}
	list := []candidate{{"udp4", "0.0.0.0", false}, {"ip4:icmp", "0.0.0.0", true}}
	if v6 {
		list = []candidate{{"udp6", "::", false}, {"ip6:ipv6-icmp", "::", true}}
	}

	var lastErr error
	for _, c := range list {
		conn, err := icmp.ListenPacket(c.network, c.address)
		if err == nil {
			return &portableProber{conn: conn, v6: v6, raw: c.raw}, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("open icmp socket: %w", lastErr)
}

func (p *portableProber) Raw() bool { return p.raw }

func (p *portableProber) Close() error { return p.conn.Close() }

func (p *portableProber) SetTTL(ttl int) error {
	if p.v6 {
		return p.conn.IPv6PacketConn().SetHopLimit(ttl)
	}
	return p.conn.IPv4PacketConn().SetTTL(ttl)
}

func (p *portableProber) Send(dst netip.Addr, seq int) error {
	msgType := icmp.Type(ipv4.ICMPTypeEcho)
	if p.v6 {
		msgType = ipv6.ICMPTypeEchoRequest
	}
	wire, err := (&icmp.Message{
		Type: msgType, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("iPulse-path-probe")},
	}).Marshal(nil)
	if err != nil {
		return err
	}
	var addr net.Addr = &net.UDPAddr{IP: dst.AsSlice()}
	if p.raw {
		addr = &net.IPAddr{IP: dst.AsSlice()}
	}
	_, err = p.conn.WriteTo(wire, addr)
	return err
}

func (p *portableProber) Receive(timeout time.Duration) (string, replyKind, int, error) {
	if timeout <= 0 {
		return "", replyNone, -1, os.ErrDeadlineExceeded
	}
	if err := p.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", replyNone, -1, err
	}
	buf := make([]byte, 1500)
	n, peer, err := p.conn.ReadFrom(buf)
	if err != nil {
		return "", replyNone, -1, err
	}
	kind, seq := parseICMP(buf[:n], p.v6, false)
	return addrOf(peer), kind, seq, nil
}
