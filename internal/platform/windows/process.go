//go:build windows

package windows

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// ProcessInfo looks up one process by pid.
func (p *Provider) ProcessInfo(pid int) (types.Process, error) { return processInfo(pid) }

// processInfo resolves a process name, image path and owning account.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberately used instead of
// PROCESS_QUERY_INFORMATION: it is the least privilege that still allows the image path
// to be read, and it works against protected processes where the wider right does not.
func processInfo(pid int) (types.Process, error) {
	proc := types.Process{PID: pid}
	if pid <= 0 {
		return proc, types.ErrNotFound
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Expected for System (pid 4), for protected processes, and for other users'
		// processes when not elevated.
		return proc, types.ErrPermission
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		proc.Exe = windows.UTF16ToString(buf[:size])
		proc.Name = filepath.Base(proc.Exe)
	}

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if tu, err := token.GetTokenUser(); err == nil && tu.User.Sid != nil {
			account, domain, _, err := tu.User.Sid.LookupAccount("")
			if err == nil {
				if domain != "" {
					proc.User = domain + `\` + account
				} else {
					proc.User = account
				}
			} else {
				proc.User = tu.User.Sid.String()
			}
		}
	}
	if proc.Name == "" {
		return proc, types.ErrPermission
	}
	return proc, nil
}
