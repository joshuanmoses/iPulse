//go:build linux

package service

import (
	"net"
	"os"
	"strings"
	"sync"
)

// sd_notify support, implemented natively.
//
// Talking to the NOTIFY_SOCKET directly avoids linking libsystemd (which would require
// cgo) while still giving systemd real readiness and watchdog signalling. Type=notify
// units start in the correct order because "ready" arrives only once iPulse is actually
// serving.
var (
	notifyOnce sync.Once
	notifyConn *net.UnixConn
)

func notifySocket() string { return os.Getenv("NOTIFY_SOCKET") }

func dialNotify() *net.UnixConn {
	notifyOnce.Do(func() {
		addr := notifySocket()
		if addr == "" {
			return
		}
		// An address starting with '@' denotes the abstract namespace, which is
		// expressed in Go with a leading NUL.
		if strings.HasPrefix(addr, "@") {
			addr = "\x00" + addr[1:]
		}
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
		if err != nil {
			return
		}
		notifyConn = conn
	})
	return notifyConn
}

// sdNotify sends a status line to systemd. It is a no-op outside systemd.
func sdNotify(state string) {
	conn := dialNotify()
	if conn == nil {
		return
	}
	_, _ = conn.Write([]byte(state))
}

// NotifyReady tells systemd that start-up is complete.
func NotifyReady() { sdNotify("READY=1") }

// NotifyStopping tells systemd that shutdown has begun.
func NotifyStopping() { sdNotify("STOPPING=1") }

// NotifyStatus publishes a one-line status string, visible in `systemctl status`.
func NotifyStatus(status string) {
	// Newlines would break the protocol's line framing.
	sdNotify("STATUS=" + strings.ReplaceAll(status, "\n", " "))
}

// NotifyWatchdog pings the systemd watchdog, if the unit enables one.
func NotifyWatchdog() { sdNotify("WATCHDOG=1") }

// WatchdogEnabled reports whether systemd expects watchdog pings.
func WatchdogEnabled() bool { return os.Getenv("WATCHDOG_USEC") != "" }
