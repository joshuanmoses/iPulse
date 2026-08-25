//go:build !linux && !windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ipulse/ipulse/internal/version"
)

// On unsupported platforms iPulse still runs in the foreground; only service
// registration is unavailable.
type stubManager struct{}

func newManager() Manager { return &stubManager{} }

func (m *stubManager) Name() string { return version.LinuxServiceName }

func (m *stubManager) Supported() (bool, string) {
	return false, "service management is implemented for systemd Linux and Windows; use `ipulse run` here"
}

func (m *stubManager) Install(InstallOptions) error     { return ErrNotSupported }
func (m *stubManager) Uninstall(UninstallOptions) error { return ErrNotSupported }
func (m *stubManager) Start() error                     { return ErrNotSupported }
func (m *stubManager) Stop() error                      { return ErrNotSupported }
func (m *stubManager) Restart() error                   { return ErrNotSupported }

func (m *stubManager) Status() (Status, error) {
	return Status{Name: version.LinuxServiceName, State: StateNotFound}, nil
}

func isService() bool { return false }

func runService(fn RunHandler) (bool, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := fn(ctx, func() {}); err != nil {
		return false, fmt.Errorf("agent: %w", err)
	}
	return false, nil
}
