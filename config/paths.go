package config

import (
	"os"
	"path/filepath"
)

// Environment variables that override path resolution. IPULSE_HOME switches iPulse
// into portable developer mode, where everything lives under one directory.
const (
	EnvHome    = "IPULSE_HOME"
	EnvConfig  = "IPULSE_CONFIG"
	EnvDataDir = "IPULSE_DATA_DIR"
	EnvLogDir  = "IPULSE_LOG_DIR"
)

// ConfigFileName is the configuration file name on every platform.
const ConfigFileName = "ipulse.yaml"

// PortableRoot returns the portable-mode root, or "" when not in portable mode.
func PortableRoot() string {
	if h := os.Getenv(EnvHome); h != "" {
		abs, err := filepath.Abs(h)
		if err != nil {
			return h
		}
		return abs
	}
	return ""
}

// DefaultConfigPath resolves the configuration file location.
func DefaultConfigPath() string {
	if p := os.Getenv(EnvConfig); p != "" {
		return p
	}
	if root := PortableRoot(); root != "" {
		return filepath.Join(root, "config", ConfigFileName)
	}
	return filepath.Join(systemConfigDir(), ConfigFileName)
}

// DefaultDataDir resolves the data directory (database and runtime state).
func DefaultDataDir() string {
	if p := os.Getenv(EnvDataDir); p != "" {
		return p
	}
	if root := PortableRoot(); root != "" {
		return filepath.Join(root, "data")
	}
	return systemDataDir()
}

// DefaultLogDir resolves the log directory.
func DefaultLogDir() string {
	if p := os.Getenv(EnvLogDir); p != "" {
		return p
	}
	if root := PortableRoot(); root != "" {
		return filepath.Join(root, "logs")
	}
	return systemLogDir()
}

// SystemConfigDir exposes the platform configuration directory for installers.
func SystemConfigDir() string { return systemConfigDir() }

// SystemDataDir exposes the platform data directory for installers.
func SystemDataDir() string { return systemDataDir() }

// SystemLogDir exposes the platform log directory for installers.
func SystemLogDir() string { return systemLogDir() }

func joinPath(dir, name string) string { return filepath.Join(dir, name) }

func isAbsPath(p string) bool { return filepath.IsAbs(p) }
