//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ipulse/ipulse/internal/version"
)

const (
	unitName = version.LinuxServiceName + ".service"
	unitPath = "/etc/systemd/system/" + unitName
)

type linuxManager struct{}

func newManager() Manager { return &linuxManager{} }

func (m *linuxManager) Name() string { return version.LinuxServiceName }

// Supported reports whether systemd is the init system. iPulse targets systemd-based
// distributions for service management; the agent itself runs anywhere.
func (m *linuxManager) Supported() (bool, string) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false, "systemd is not running on this host (/run/systemd/system is absent); " +
			"run iPulse in the foreground with `ipulse run`, or add a unit for your init system"
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, "systemctl was not found in PATH"
	}
	return true, ""
}

// Install writes the unit file and registers the service.
func (m *linuxManager) Install(opts InstallOptions) error {
	if ok, why := m.Supported(); !ok {
		return fmt.Errorf("%w: %s", ErrNotSupported, why)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("service: installing %s requires root", unitName)
	}
	exe := opts.ExecPath
	if exe == "" {
		var err error
		if exe, err = executablePath(); err != nil {
			return err
		}
	}
	unit, err := renderUnitPortable(exe, opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("service: write %s: %w", unitPath, err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if opts.Enable {
		if err := systemctl("enable", unitName); err != nil {
			return err
		}
	}
	if opts.Start {
		if err := systemctl("start", unitName); err != nil {
			return err
		}
	}
	return nil
}

func (m *linuxManager) Uninstall(opts UninstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service: removing %s requires root", unitName)
	}
	// Best effort: a service that is already stopped or disabled must not fail removal.
	_ = systemctl("stop", unitName)
	_ = systemctl("disable", unitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("service: remove %s: %w", unitPath, err)
	}
	_ = systemctl("daemon-reload")
	_ = systemctl("reset-failed", unitName)

	if !opts.KeepData {
		for _, dir := range []string{opts.DataDir, opts.LogDir} {
			if dir == "" || !isSafeToRemove(dir) {
				continue
			}
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("service: remove %s: %w", dir, err)
			}
		}
	}
	return nil
}

// isSafeToRemove refuses to delete anything that is not clearly an iPulse directory.
// An uninstaller that can be pointed at / by a misconfigured value is a liability.
func isSafeToRemove(dir string) bool {
	clean := filepath.Clean(dir)
	if clean == "/" || clean == "." || clean == "" {
		return false
	}
	return strings.Contains(clean, "ipulse") || strings.Contains(clean, "iPulse")
}

func (m *linuxManager) Start() error   { return systemctl("start", unitName) }
func (m *linuxManager) Stop() error    { return systemctl("stop", unitName) }
func (m *linuxManager) Restart() error { return systemctl("restart", unitName) }

func (m *linuxManager) Status() (Status, error) {
	st := Status{Name: version.LinuxServiceName, State: StateUnknown}
	if _, err := os.Stat(unitPath); err != nil {
		st.State = StateNotFound
		return st, nil
	}
	st.Installed = true

	// systemctl show gives machine-readable key=value output, which is far safer to
	// parse than the human-facing status text.
	out, err := systemctlOutput("show", unitName,
		"--property=ActiveState,SubState,MainPID,UnitFileState,Result")
	if err != nil {
		return st, err
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	switch props["ActiveState"] {
	case "active":
		st.State = StateRunning
	case "activating":
		st.State = StateStarting
	case "deactivating":
		st.State = StateStopping
	case "failed":
		st.State = StateFailed
	case "inactive":
		st.State = StateStopped
	}
	if pid, err := strconv.Atoi(props["MainPID"]); err == nil && pid > 0 {
		st.PID = pid
	}
	st.StartType = props["UnitFileState"]
	if props["Result"] != "" && props["Result"] != "success" {
		st.Detail = "result=" + props["Result"]
	}
	return st, nil
}

// systemctl runs systemctl with fixed arguments. exec.Command does not involve a shell,
// and every argument here is either a constant or a validated unit name, so there is no
// injection surface.
func systemctl(args ...string) error {
	out, err := systemctlOutput(args...)
	if err != nil {
		return fmt.Errorf("service: systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func systemctlOutput(args ...string) (string, error) {
	cmd := exec.Command("systemctl", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0")
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// UnitFileContents renders the unit that Install would write, without touching the
// filesystem. Packaging uses it so a packaged unit and an installed one can never drift.
func UnitFileContents(exe string, opts InstallOptions) (string, error) {
	return renderUnitPortable(exe, opts)
}

// isService reports whether systemd started this process. INVOCATION_ID is set by
// systemd for every unit it starts.
func isService() bool {
	return os.Getenv("INVOCATION_ID") != "" || notifySocket() != ""
}

// runService runs the agent, translating signals into context cancellation and
// forwarding readiness to systemd.
func runService(fn RunHandler) (bool, error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	managed := isService()
	err := fn(ctx, func() {
		NotifyReady()
		NotifyStatus("monitoring")
	})
	NotifyStopping()
	return managed, err
}
