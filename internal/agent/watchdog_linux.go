//go:build linux

package agent

import (
	"os"
	"strconv"
	"time"

	"github.com/ipulse/ipulse/internal/service"
)

func watchdogEnabled() bool { return service.WatchdogEnabled() }

func watchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}

func notifyWatchdog() { service.NotifyWatchdog() }
