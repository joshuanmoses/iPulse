package latency

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
)

// probeTCP times TCP handshakes when ICMP is unavailable.
//
// A refused connection still counts as a successful measurement: the remote host
// answered, which is exactly what a latency probe is asking. Only a timeout counts as
// loss. Treating a refusal as loss would report 100 % packet loss against any host with
// the probe port closed, which is a common and misleading failure mode in other tools.
func (p *Prober) probeTCP(ctx context.Context, target string) Result {
	res := Result{Target: target, Method: MethodTCP}

	host, port := target, strconv.Itoa(p.cfg.TCPPort)
	if h, pt, err := net.SplitHostPort(target); err == nil {
		host, port = h, pt
	}
	if ip := net.ParseIP(host); ip != nil {
		res.Resolved = ip.String()
	}
	address := net.JoinHostPort(host, port)

	dialer := net.Dialer{Timeout: p.cfg.Timeout}
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
		res.Sent++

		attemptCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
		start := time.Now()
		conn, err := dialer.DialContext(attemptCtx, "tcp", address)
		rtt := time.Since(start)
		cancel()

		switch {
		case err == nil:
			res.RTTs = append(res.RTTs, rtt)
			res.Recv++
			_ = conn.Close()
		case isConnectionRefused(err):
			// The host is reachable and answered with a reset.
			res.RTTs = append(res.RTTs, rtt)
			res.Recv++
		default:
			res.Err = fmt.Errorf("connect %s: %w", address, err)
		}
	}
	return finish(&res)
}

func isConnectionRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// Windows reports WSAECONNREFUSED (10061), which is not syscall.ECONNREFUSED there.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *syscall.Errno
		if errors.As(opErr.Err, &sysErr) && uintptr(*sysErr) == 10061 {
			return true
		}
	}
	return false
}
