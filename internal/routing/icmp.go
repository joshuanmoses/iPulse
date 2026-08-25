package routing

import (
	"encoding/binary"
)

// ICMP message types used by path measurement.
const (
	icmpv4Echo         = 8
	icmpv4EchoReply    = 0
	icmpv4TimeExceeded = 11
	icmpv4DestUnreach  = 3
	icmpv6EchoRequest  = 128
	icmpv6EchoReply    = 129
	icmpv6TimeExceeded = 3
	icmpv6DestUnreach  = 1
)

// buildEcho assembles an ICMP echo request.
//
// The checksum is computed here for IPv4; for ICMPv6 the kernel computes it, because the
// pseudo-header includes addresses the socket layer chooses.
func buildEcho(v6 bool, id, seq int) []byte {
	const payload = "iPulse-path-probe"
	msg := make([]byte, 8+len(payload))
	if v6 {
		msg[0] = icmpv6EchoRequest
	} else {
		msg[0] = icmpv4Echo
	}
	msg[1] = 0 // code
	binary.BigEndian.PutUint16(msg[4:6], uint16(id))
	binary.BigEndian.PutUint16(msg[6:8], uint16(seq))
	copy(msg[8:], payload)
	if !v6 {
		binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
	}
	return msg
}

// parseICMP identifies a received ICMP message and extracts the sequence number of the
// probe it refers to. Raw sockets deliver the IP header as well, which is skipped.
func parseICMP(b []byte, v6, raw bool) (replyKind, int) {
	if raw && !v6 && len(b) > 0 {
		headerLen := int(b[0]&0x0f) * 4
		if headerLen >= 20 && len(b) > headerLen {
			b = b[headerLen:]
		}
	}
	if len(b) < 8 {
		return replyNone, -1
	}
	msgType := b[0]
	seq := int(binary.BigEndian.Uint16(b[6:8]))

	switch {
	case !v6 && msgType == icmpv4EchoReply:
		return replyEcho, seq
	case v6 && msgType == icmpv6EchoReply:
		return replyEcho, seq
	case !v6 && msgType == icmpv4TimeExceeded, v6 && msgType == icmpv6TimeExceeded:
		return replyTimeExceeded, embeddedSeq(b[8:], v6)
	case !v6 && msgType == icmpv4DestUnreach, v6 && msgType == icmpv6DestUnreach:
		return replyUnreachable, embeddedSeq(b[8:], v6)
	}
	return replyNone, -1
}

// checksum is the standard one's-complement Internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
