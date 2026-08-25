//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Minimal generic-netlink client.
//
// iPulse speaks netlink directly rather than shelling out to `iw` or linking libnl:
// there is no external binary to be missing, no output format to be broken by a version
// change, and no cgo. Only the small subset needed for wireless telemetry is here.

const (
	nlmsgHdrLen  = 16 // sizeof(struct nlmsghdr)
	genlHdrLen   = 4  // sizeof(struct genlmsghdr)
	nlmsgAlignTo = 4

	genlIDCtrl        = 0x10
	ctrlCmdGetFamily  = 3
	ctrlAttrFamilyID  = 1
	ctrlAttrFamilyNam = 2
)

func nlAlign(n int) int { return (n + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1) }

// genlConn is a generic-netlink socket.
type genlConn struct {
	fd  int
	seq uint32
	pid uint32
}

func dialGenetlink() (*genlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return nil, fmt.Errorf("netlink: socket: %w", err)
	}
	// Bind with pid 0 so the kernel assigns a unique port id; hard-coding getpid()
	// breaks as soon as two goroutines or two processes open a socket.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink: bind: %w", err)
	}
	// Bound receive buffer: a scan dump on a busy band can be large, but iPulse must
	// not allocate without limit.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// A read timeout guarantees a hung kernel path cannot wedge a collector.
	tv := unix.NsecToTimeval(int64(3e9))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	sa, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		_ = unix.Close(fd)
		return nil, errors.New("netlink: unexpected socket address type")
	}
	return &genlConn{fd: fd, pid: nl.Pid}, nil
}

func (c *genlConn) close() error { return unix.Close(c.fd) }

// request sends one generic-netlink command and returns the payload of each reply
// message (the bytes following the genlmsghdr).
func (c *genlConn) request(family uint16, cmd uint8, dump bool, attrs []byte) ([][]byte, error) {
	c.seq++
	seq := c.seq

	total := nlmsgHdrLen + genlHdrLen + len(attrs)
	msg := make([]byte, nlAlign(total))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(total))
	binary.NativeEndian.PutUint16(msg[4:6], family)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if dump {
		flags = uint16(unix.NLM_F_REQUEST | unix.NLM_F_DUMP)
	}
	binary.NativeEndian.PutUint16(msg[6:8], flags)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	binary.NativeEndian.PutUint32(msg[12:16], c.pid)
	msg[16] = cmd // genlmsghdr.cmd
	msg[17] = 1   // genlmsghdr.version
	copy(msg[nlmsgHdrLen+genlHdrLen:], attrs)

	if err := unix.Sendto(c.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink: send: %w", err)
	}

	var payloads [][]byte
	buf := make([]byte, 1<<17)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				// Timed out: return whatever arrived rather than blocking a collector.
				return payloads, nil
			}
			return payloads, fmt.Errorf("netlink: receive: %w", err)
		}
		data := buf[:n]
		for len(data) >= nlmsgHdrLen {
			msgLen := int(binary.NativeEndian.Uint32(data[0:4]))
			msgType := binary.NativeEndian.Uint16(data[4:6])
			msgSeq := binary.NativeEndian.Uint32(data[8:12])
			if msgLen < nlmsgHdrLen || msgLen > len(data) {
				return payloads, errors.New("netlink: truncated message")
			}
			body := data[nlmsgHdrLen:msgLen]
			data = data[nlAlign(msgLen):]

			// Messages from an earlier request (a trailing ACK, for example) must be
			// skipped rather than mistaken for the end of this one.
			if msgSeq != seq {
				continue
			}

			switch msgType {
			case unix.NLMSG_ERROR:
				if len(body) < 4 {
					return payloads, errors.New("netlink: malformed error message")
				}
				if code := int32(binary.NativeEndian.Uint32(body[0:4])); code != 0 {
					return payloads, fmt.Errorf("netlink: kernel error: %w", unix.Errno(-code))
				}
				// A zero code is an ACK, which terminates a non-dump request.
				if !dump {
					return payloads, nil
				}
			case unix.NLMSG_DONE:
				return payloads, nil
			default:
				if len(body) >= genlHdrLen {
					// Copy: buf is reused by the next Recvfrom.
					p := make([]byte, len(body)-genlHdrLen)
					copy(p, body[genlHdrLen:])
					payloads = append(payloads, p)
				}
			}
		}
	}
}

// resolveFamily looks up a generic-netlink family id by name.
func (c *genlConn) resolveFamily(name string) (uint16, error) {
	attrs := putAttrString(nil, ctrlAttrFamilyNam, name)
	replies, err := c.request(genlIDCtrl, ctrlCmdGetFamily, false, attrs)
	if err != nil {
		return 0, err
	}
	for _, r := range replies {
		attrs, err := parseAttrs(r)
		if err != nil {
			continue
		}
		if v, ok := attrs[ctrlAttrFamilyID]; ok && len(v) >= 2 {
			return binary.NativeEndian.Uint16(v), nil
		}
	}
	return 0, fmt.Errorf("netlink: generic family %q not available", name)
}

// --- attribute encoding/decoding --------------------------------------------

func putAttr(dst []byte, typ uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.NativeEndian.PutUint16(hdr[0:2], uint16(4+len(data)))
	binary.NativeEndian.PutUint16(hdr[2:4], typ)
	dst = append(dst, hdr...)
	dst = append(dst, data...)
	for pad := nlAlign(len(data)) - len(data); pad > 0; pad-- {
		dst = append(dst, 0)
	}
	return dst
}

func putAttrString(dst []byte, typ uint16, s string) []byte {
	return putAttr(dst, typ, append([]byte(s), 0))
}

func putAttrU32(dst []byte, typ uint16, v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return putAttr(dst, typ, b[:])
}

// parseAttrs decodes a flat netlink attribute stream. Duplicate types keep the last
// occurrence, matching kernel parsing behaviour.
func parseAttrs(b []byte) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		typ := binary.NativeEndian.Uint16(b[2:4]) & 0x3fff // strip NESTED/BYTE_ORDER flags
		if length < 4 || length > len(b) {
			return out, errors.New("netlink: malformed attribute")
		}
		out[typ] = b[4:length]
		b = b[nlAlign(length):]
	}
	return out, nil
}

func attrU32(v []byte) uint32 {
	if len(v) < 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(v)
}

func attrU16(v []byte) uint16 {
	if len(v) < 2 {
		return 0
	}
	return binary.NativeEndian.Uint16(v)
}

func attrS32(v []byte) int32 { return int32(attrU32(v)) }

func attrS8(v []byte) int8 {
	if len(v) < 1 {
		return 0
	}
	return int8(v[0])
}

func attrString(v []byte) string {
	for i, c := range v {
		if c == 0 {
			return string(v[:i])
		}
	}
	return string(v)
}

// selfPID is used only for diagnostics.
func selfPID() uint32 { return uint32(os.Getpid()) }

// unusedUnsafe keeps the unsafe import meaningful if future struct casting is added.
var _ = unsafe.Sizeof(0)
