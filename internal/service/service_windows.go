//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ipulse/ipulse/internal/logging"
	"github.com/ipulse/ipulse/internal/version"
)

type windowsManager struct{}

func newManager() Manager { return &windowsManager{} }

func (m *windowsManager) Name() string { return version.WinServiceName }

func (m *windowsManager) Supported() (bool, string) { return true, "" }

// Install registers the service with the Service Control Manager and configures
// automatic start with delayed start and failure recovery.
func (m *windowsManager) Install(opts InstallOptions) error {
	exe := opts.ExecPath
	if exe == "" {
		var err error
		if exe, err = executablePath(); err != nil {
			return err
		}
	}
	args := []string{"service", "run"}
	if opts.ConfigPath != "" {
		args = append(args, "--config", opts.ConfigPath)
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to the service manager (Administrator required): %w", err)
	}
	defer scm.Disconnect()

	if s, err := scm.OpenService(version.WinServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service: %s is already installed", version.WinServiceName)
	}

	cfg := mgr.Config{
		DisplayName:      version.WinDisplayName,
		Description:      version.Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: "LocalSystem",
		// The extended socket tables and the WLAN API need LocalSystem; the dashboard
		// and API remain bound to loopback and are never exposed by this choice.
	}
	if !opts.Enable {
		cfg.StartType = mgr.StartManual
	}

	s, err := scm.CreateService(version.WinServiceName, exe, cfg, args...)
	if err != nil {
		return fmt.Errorf("service: create %s: %w", version.WinServiceName, err)
	}
	defer s.Close()

	// Restart on failure: two restarts a minute apart, then give up and leave the
	// failure visible rather than looping forever.
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.NoAction},
	}
	if err := s.SetRecoveryActions(recovery, uint32(86400)); err != nil {
		// Not fatal: the service is installed and usable.
		_ = err
	}

	if err := logging.InstallEventLogSource(); err != nil {
		return fmt.Errorf("service: register the Windows Event Log source: %w", err)
	}
	if opts.Start {
		if err := s.Start(); err != nil {
			return fmt.Errorf("service: start %s: %w", version.WinServiceName, err)
		}
	}
	return nil
}

func (m *windowsManager) Uninstall(opts UninstallOptions) error {
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to the service manager (Administrator required): %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(version.WinServiceName)
	if err != nil {
		if !opts.KeepData {
			removeDataDirs(opts)
		}
		return nil // already gone
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			waitForState(s, svc.Stopped, 30*time.Second)
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("service: delete %s: %w", version.WinServiceName, err)
	}
	_ = logging.RemoveEventLogSource()

	if !opts.KeepData {
		removeDataDirs(opts)
	}
	return nil
}

func removeDataDirs(opts UninstallOptions) {
	for _, dir := range []string{opts.DataDir, opts.LogDir} {
		if dir == "" || !isSafeToRemove(dir) {
			continue
		}
		_ = os.RemoveAll(dir)
	}
}

// isSafeToRemove refuses to delete anything that is not clearly an iPulse directory.
func isSafeToRemove(dir string) bool {
	clean := filepath.Clean(dir)
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return false
	}
	if vol := filepath.VolumeName(clean); vol != "" && len(clean) <= len(vol)+1 {
		return false
	}
	lower := strings.ToLower(clean)
	return strings.Contains(lower, "ipulse")
}

func (m *windowsManager) Start() error {
	s, scm, err := openService()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	defer s.Close()
	return s.Start()
}

func (m *windowsManager) Stop() error {
	s, scm, err := openService()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	return waitForState(s, svc.Stopped, 30*time.Second)
}

func (m *windowsManager) Restart() error {
	if err := m.Stop(); err != nil && !errors.Is(err, syscall.Errno(1062)) { // not started
		return err
	}
	return m.Start()
}

func (m *windowsManager) Status() (Status, error) {
	st := Status{Name: version.WinServiceName, State: StateUnknown}
	s, scm, err := openService()
	if err != nil {
		st.State = StateNotFound
		return st, nil
	}
	defer scm.Disconnect()
	defer s.Close()
	st.Installed = true

	q, err := s.Query()
	if err != nil {
		return st, err
	}
	switch q.State {
	case svc.Running:
		st.State = StateRunning
	case svc.Stopped:
		st.State = StateStopped
	case svc.StartPending:
		st.State = StateStarting
	case svc.StopPending:
		st.State = StateStopping
	}
	st.PID = int(q.ProcessId)
	if cfg, err := s.Config(); err == nil {
		switch cfg.StartType {
		case mgr.StartAutomatic:
			st.StartType = "automatic"
			if cfg.DelayedAutoStart {
				st.StartType = "automatic (delayed)"
			}
		case mgr.StartManual:
			st.StartType = "manual"
		case mgr.StartDisabled:
			st.StartType = "disabled"
		}
	}
	return st, nil
}

func openService() (*mgr.Service, *mgr.Mgr, error) {
	scm, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("service: connect to the service manager: %w", err)
	}
	s, err := scm.OpenService(version.WinServiceName)
	if err != nil {
		scm.Disconnect()
		return nil, nil, fmt.Errorf("service: %s is not installed: %w", version.WinServiceName, err)
	}
	return s, scm, nil
}

func waitForState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		q, err := s.Query()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("service: timed out waiting for state %d", want)
}

// isService reports whether the Service Control Manager started this process.
func isService() bool {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return inService
}

// ipulseHandler bridges the SCM control protocol to a context.
type ipulseHandler struct {
	fn RunHandler
	// errCh carries the agent's exit error back to Execute.
	errCh chan error
}

// Execute implements svc.Handler.
func (h *ipulseHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := func() { changes <- svc.Status{State: svc.Running, Accepts: accepted} }
	go func() { h.errCh <- h.fn(ctx, ready) }()

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-h.errCh:
					if err != nil {
						return true, 1
					}
				case <-time.After(30 * time.Second):
					return true, 1
				}
				return false, 0
			case svc.ParamChange:
				// A configuration reload request: the agent watches its own file, so
				// this is acknowledged and handled there.
				changes <- c.CurrentStatus
			default:
				changes <- c.CurrentStatus
			}
		case err := <-h.errCh:
			// The agent exited on its own: report a failure so the SCM's recovery
			// actions apply.
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

// runService runs the agent under the SCM when started as a service, and in the
// foreground (Ctrl-C aware) otherwise.
func runService(fn RunHandler) (bool, error) {
	if isService() {
		h := &ipulseHandler{fn: fn, errCh: make(chan error, 1)}
		if err := svc.Run(version.WinServiceName, h); err != nil {
			return true, fmt.Errorf("service: run: %w", err)
		}
		return true, nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return false, fn(ctx, func() {})
}
