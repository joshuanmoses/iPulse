//go:build !linux

package service

// The sd_notify protocol is Linux-only; these are no-ops elsewhere so callers need no
// build tags.

// NotifyReady is a no-op off Linux.
func NotifyReady() {}

// NotifyStopping is a no-op off Linux.
func NotifyStopping() {}

// NotifyStatus is a no-op off Linux.
func NotifyStatus(string) {}

// NotifyWatchdog is a no-op off Linux.
func NotifyWatchdog() {}

// WatchdogEnabled always reports false off Linux.
func WatchdogEnabled() bool { return false }
