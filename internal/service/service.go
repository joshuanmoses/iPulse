// Package service manages the iPulse service lifecycle on both platforms: installing
// and removing the service, starting and stopping it, reporting its status, and running
// the agent under the platform's service supervisor.
//
// The platform-specific pieces are systemd (unit file plus sd_notify readiness) and the
// Windows Service Control Manager (svc handler plus mgr registration).
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// State is the coarse service state reported by the platform.
type State string

// Service states.
const (
	StateRunning  State = "running"
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateStopping State = "stopping"
	StateFailed   State = "failed"
	StateNotFound State = "not-installed"
	StateUnknown  State = "unknown"
)

// Status describes the installed service.
type Status struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	State     State  `json:"state"`
	PID       int    `json:"pid,omitempty"`
	StartType string `json:"start_type,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// InstallOptions configures service registration.
type InstallOptions struct {
	// ExecPath is the absolute path of the installed binary. Defaults to the running
	// executable.
	ExecPath string
	// ConfigPath is passed to the service as --config.
	ConfigPath string
	// User is the account the service runs as (Linux only; Windows uses LocalSystem).
	User string
	// Group is the Linux group.
	Group string
	// DataDir and LogDir are used to write the unit's directory declarations.
	DataDir string
	LogDir  string
	// Enable starts the service at boot.
	Enable bool
	// Start starts the service immediately after installation.
	Start bool
}

// UninstallOptions configures service removal.
type UninstallOptions struct {
	// KeepData preserves the database and logs.
	KeepData  bool
	DataDir   string
	LogDir    string
	ConfigDir string
}

// Manager controls the platform service.
type Manager interface {
	// Name is the platform service name (ipulse, or iPulse on Windows).
	Name() string
	Install(opts InstallOptions) error
	Uninstall(opts UninstallOptions) error
	Start() error
	Stop() error
	Restart() error
	Status() (Status, error)
	// Supported reports whether service management is available on this host, and why
	// not when it is unavailable (no systemd, for example).
	Supported() (bool, string)
}

// ErrNotSupported is returned when the host has no supported service manager.
var ErrNotSupported = errors.New("service: no supported service manager on this host")

// NewManager returns the platform service manager.
func NewManager() Manager { return newManager() }

// RunHandler is the agent entry point a service supervisor invokes. Ready must be
// called once the agent is serving, so the supervisor can report start-up completion.
type RunHandler func(ctx context.Context, ready func()) error

// Run executes fn under the platform service supervisor when the process was started as
// a service, and directly in the foreground otherwise. The bool result reports whether
// the process was running as a managed service.
func Run(fn RunHandler) (bool, error) { return runService(fn) }

// IsService reports whether this process was started by the platform service manager.
func IsService() bool { return isService() }

// executablePath returns the absolute path of the running binary, resolving symlinks so
// a unit file records the real target.
func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Abs(exe)
}

// quoteArg renders an argument for a unit file or service command line. Arguments come
// from configuration and installer flags, so they are quoted rather than interpolated
// raw, and a value containing a quote is rejected outright.
func quoteArg(s string) (string, error) {
	if strings.ContainsAny(s, "\"\n\r") {
		return "", fmt.Errorf("service: argument %q contains characters that cannot be quoted safely", s)
	}
	if s == "" {
		return `""`, nil
	}
	if !strings.ContainsAny(s, " \t\\") {
		return s, nil
	}
	return `"` + s + `"`, nil
}
