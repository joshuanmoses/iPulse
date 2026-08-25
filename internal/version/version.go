// Package version carries build metadata, injected at link time.
package version

import (
	"fmt"
	"runtime"
)

// These values are overridden with -ldflags at build time by scripts/build.sh.
var (
	// Version is the semantic version of this build.
	Version = "1.0.0"
	// Commit is the source revision.
	Commit = "unknown"
	// BuildDate is the RFC 3339 build timestamp.
	BuildDate = "unknown"
)

// Product names used for service registration, log sources and the dashboard title.
const (
	Product          = "iPulse"
	Description      = "iPulse Internet connection monitoring and network observability agent"
	LinuxServiceName = "ipulse"
	WinServiceName   = "iPulse"
	WinDisplayName   = "iPulse Service"
	UserAgent        = "iPulse/" + "1.0"
)

// String renders a one-line version summary.
func String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s)",
		Product, Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Platform returns the os/arch pair.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
