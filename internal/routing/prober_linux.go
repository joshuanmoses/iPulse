//go:build linux

package routing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// The Linux prober owns its socket directly rather than going through a higher-level
// helper, because path measurement needs something those helpers do not expose: the
// socket error queue.
//
// On Linux an unprivileged datagram ICMP socket (SOCK_DGRAM, IPPROTO_ICMP) can send echo
// requests without CAP_NET_RAW, but the ICMP "time exceeded" replies from intermediate
// routers are not delivered as ordinary datagrams. They arrive as socket errors, readable
// only from the error queue with MSG_ERRQUEUE once IP_RECVERR is enabled. Reading that
// queue is what lets iPulse measure a full path on a normal host with no elevated
// privileges at all - which is exactly what the hardened service unit provides.
type linuxProber struct {
	fd  int
	v6  bool
	raw bool
}

func newProber(v6 bool) (prober, error) {
	domain, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if v6 {
		domain, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}

	// Try the unprivileged datagram socket first.
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	raw := false
	if err != nil {
		// Fall back to a raw socket, which needs CAP_NET_RAW.
		fd, err = unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
		if err != nil {
			return nil, fmt.Errorf("open icmp socket: %w", err)
		}
		raw = true
	}

	p := &linuxProber{fd: fd, v6: v6, raw: raw}
	if err := p.bindLocal(domain); err != nil {
		_ = p.Close()
		return nil, err
	}
	// Enable the error queue: without this, intermediate hops are invisible.
	if v6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("enable IPV6_RECVERR: %w", err)
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("enable IP_RECVERR: %w", err)
		}
	}
	return p, nil
}

func (p *linuxProber) bindLocal(domain int) error {
	if domain == unix.AF_INET6 {
		return unix.Bind(p.fd, &unix.SockaddrInet6{})
	}
	return unix.Bind(p.fd, &unix.SockaddrInet4{})
}

func (p *linuxProber) Raw() bool { return p.raw }

func (p *linuxProber) Close() error { return unix.Close(p.fd) }

func (p *linuxProber) SetTTL(ttl int) error {
	if p.v6 {
		return unix.SetsockoptInt(p.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
	}
	return unix.SetsockoptInt(p.fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
}

func (p *linuxProber) Send(dst netip.Addr, seq int) error {
	packet := buildEcho(p.v6, os.Getpid()&0xffff, seq)
	if p.v6 {
		var sa unix.SockaddrInet6
		sa.Addr = dst.As16()
		return unix.Sendto(p.fd, packet, 0, &sa)
	}
	var sa unix.SockaddrInet4
	sa.Addr = dst.Unmap().As4()
	return unix.Sendto(p.fd, packet, 0, &sa)
}

// Receive waits for either an ordinary reply or an error-queue entry.
func (p *linuxProber) Receive(timeout time.Duration) (string, replyKind, int, error) {
	if timeout <= 0 {
		return "", replyNone, -1, os.ErrDeadlineExceeded
	}
	fds := []unix.PollFd{{
		Fd: int32(p.fd),
		// POLLERR signals that the error queue has something for us.
		Events: unix.POLLIN | unix.POLLERR,
	}}
	n, err := unix.Poll(fds, int(timeout.Milliseconds()))
	if err != nil {
		if err == unix.EINTR {
			return "", replyNone, -1, nil
		}
		return "", replyNone, -1, err
	}
	if n == 0 {
		return "", replyNone, -1, os.ErrDeadlineExceeded
	}

	// The error queue first: a time-exceeded reply is the interesting case, and it is
	// what POLLERR is reporting.
	if fds[0].Revents&unix.POLLERR != 0 {
		if addr, kind, seq, ok := p.readErrQueue(); ok {
			return addr, kind, seq, nil
		}
	}
	if fds[0].Revents&unix.POLLIN != 0 {
		return p.readNormal()
	}
	return "", replyNone, -1, nil
}

// readNormal reads an ordinary datagram, which for this socket means an echo reply.
func (p *linuxProber) readNormal() (string, replyKind, int, error) {
	buf := make([]byte, 1500)
	n, from, err := unix.Recvfrom(p.fd, buf, unix.MSG_DONTWAIT)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return "", replyNone, -1, nil
		}
		return "", replyNone, -1, err
	}
	addr := sockaddrString(from)
	kind, seq := parseICMP(buf[:n], p.v6, p.raw)
	return addr, kind, seq, nil
}

// readErrQueue reads one entry from the socket error queue and extracts the offending
// router's address and the sequence number of the probe it refers to.
func (p *linuxProber) readErrQueue() (string, replyKind, int, bool) {
	buf := make([]byte, 1500)
	oob := make([]byte, 1024)
	n, oobn, _, _, err := unix.Recvmsg(p.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return "", replyNone, -1, false
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return "", replyNone, -1, false
	}
	for _, m := range msgs {
		wantLevel, wantType := unix.IPPROTO_IP, unix.IP_RECVERR
		if p.v6 {
			wantLevel, wantType = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
		}
		if m.Header.Level != int32(wantLevel) || m.Header.Type != int32(wantType) {
			continue
		}
		addr, kind, ok := parseExtendedErr(m.Data, p.v6)
		if !ok {
			continue
		}
		// The returned payload is the original packet we sent, so its sequence number
		// identifies the probe.
		seq := -1
		if n >= 8 {
			seq = int(binary.BigEndian.Uint16(buf[6:8]))
		}
		return addr, kind, seq, true
	}
	return "", replyNone, -1, false
}

// parseExtendedErr decodes struct sock_extended_err followed by the offender address.
//
//	struct sock_extended_err {
//	    __u32 ee_errno;  __u8 ee_origin; __u8 ee_type;
//	    __u8  ee_code;   __u8 ee_pad;    __u32 ee_info; __u32 ee_data;
//	};
func parseExtendedErr(data []byte, v6 bool) (string, replyKind, bool) {
	const extendedErrLen = 16
	if len(data) < extendedErrLen {
		return "", replyNone, false
	}
	origin := data[4]
	errType := data[5]

	const (
		originICMP        = 2 // SO_EE_ORIGIN_ICMP
		originICMP6       = 3 // SO_EE_ORIGIN_ICMP6
		icmpTimeExceeded  = 11
		icmp6TimeExceeded = 3
		icmpDestUnreach   = 3
		icmp6DestUnreach  = 1
	)

	var kind replyKind
	switch {
	case !v6 && origin == originICMP && errType == icmpTimeExceeded:
		kind = replyTimeExceeded
	case !v6 && origin == originICMP && errType == icmpDestUnreach:
		kind = replyUnreachable
	case v6 && origin == originICMP6 && errType == icmp6TimeExceeded:
		kind = replyTimeExceeded
	case v6 && origin == originICMP6 && errType == icmp6DestUnreach:
		kind = replyUnreachable
	default:
		return "", replyNone, false
	}

	// The offender's sockaddr follows the structure.
	offender := data[extendedErrLen:]
	if v6 {
		// struct sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4)
		if len(offender) < 24 {
			return "", kind, false
		}
		var a [16]byte
		copy(a[:], offender[8:24])
		return netip.AddrFrom16(a).Unmap().String(), kind, true
	}
	// struct sockaddr_in: family(2) port(2) addr(4)
	if len(offender) < 8 {
		return "", kind, false
	}
	var a [4]byte
	copy(a[:], offender[4:8])
	return netip.AddrFrom4(a).String(), kind, true
}

func sockaddrString(sa unix.Sockaddr) string {
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(v.Addr).String()
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(v.Addr).Unmap().String()
	}
	return ""
}
