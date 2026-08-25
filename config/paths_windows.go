//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// programData returns %ProgramData%\iPulse, falling back to the conventional path if
// the environment variable is missing (which happens in some service contexts).
func programData() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "iPulse")
	}
	if sd := os.Getenv("SystemDrive"); sd != "" {
		return filepath.Join(sd+`\`, "ProgramData", "iPulse")
	}
	return `C:\ProgramData\iPulse`
}

func systemConfigDir() string { return filepath.Join(programData(), "config") }
func systemDataDir() string   { return filepath.Join(programData(), "data") }
func systemLogDir() string    { return filepath.Join(programData(), "logs") }

// RunDir is where the state file lives when running as a service.
func RunDir() string { return filepath.Join(programData(), "run") }
