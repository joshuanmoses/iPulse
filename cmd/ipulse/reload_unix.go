//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// registerReloadSignal subscribes to SIGHUP, the conventional reload signal.
func registerReloadSignal(ch chan os.Signal) { signal.Notify(ch, syscall.SIGHUP) }
