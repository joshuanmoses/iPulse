//go:build !linux

package agent

import "time"

func watchdogEnabled() bool           { return false }
func watchdogInterval() time.Duration { return 0 }
func notifyWatchdog()                 {}
