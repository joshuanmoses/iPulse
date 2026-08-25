//go:build !windows

package config

// Filesystem layout on Linux and other Unix systems, following the FHS.
func systemConfigDir() string { return "/etc/ipulse" }
func systemDataDir() string   { return "/var/lib/ipulse" }
func systemLogDir() string    { return "/var/log/ipulse" }

// RunDir is where the pid/state file lives when running as a system service.
func RunDir() string { return "/run/ipulse" }
