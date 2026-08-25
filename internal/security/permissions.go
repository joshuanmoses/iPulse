package security

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Directory and file permissions iPulse enforces on its own data.
//
// The data directory holds connection metadata: which application talked to which
// destination and when. That is sensitive, so it is not world-readable, and the
// permissions are re-applied at every start-up rather than trusted to whatever the
// installer or an administrator left behind.
const (
	DirMode        os.FileMode = 0o750
	DataFileMode   os.FileMode = 0o640
	ConfigFileMode os.FileMode = 0o640
	// SecretFileMode is for anything holding a token.
	SecretFileMode os.FileMode = 0o600
)

// EnsureDir creates a directory with the required mode and tightens it if it already
// exists with looser permissions.
func EnsureDir(path string, mode os.FileMode) error {
	if path == "" {
		return fmt.Errorf("security: empty directory path")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("security: create %s: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		// POSIX modes are not meaningful on Windows; the installer sets ACLs instead.
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&^mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("security: tighten permissions on %s: %w", path, err)
		}
	}
	return nil
}

// EnsureFileMode tightens an existing file's permissions.
func EnsureFileMode(path string, mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode().Perm()&^mode != 0 {
		return os.Chmod(path, mode)
	}
	return nil
}

// PathWarning describes a permission problem worth reporting but not worth refusing to
// start over.
type PathWarning struct {
	Path   string
	Reason string
}

func (w PathWarning) String() string { return w.Path + ": " + w.Reason }

// AuditPaths checks the directories and files iPulse relies on and reports anything
// unsafe: world-writable directories, world-readable data, or a configuration file
// writable by other users (which would let a local user redirect monitoring).
func AuditPaths(configPath, dataDir, logDir string) []PathWarning {
	if runtime.GOOS == "windows" {
		return nil
	}
	var out []PathWarning

	check := func(path string, maxPerm os.FileMode, what string) {
		if path == "" {
			return
		}
		st, err := os.Stat(path)
		if err != nil {
			return
		}
		perm := st.Mode().Perm()
		if perm&0o002 != 0 {
			out = append(out, PathWarning{path, what + " is writable by any local user"})
			return
		}
		if extra := perm & ^maxPerm; extra != 0 {
			out = append(out, PathWarning{path,
				fmt.Sprintf("%s has permissions %04o, tighter than %04o is recommended", what, perm, maxPerm)})
		}
	}

	if configPath != "" {
		check(configPath, ConfigFileMode, "configuration file")
		check(filepath.Dir(configPath), DirMode, "configuration directory")
	}
	check(dataDir, DirMode, "data directory")
	check(logDir, DirMode, "log directory")
	return out
}
