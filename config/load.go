package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadResult carries a loaded configuration together with everything the caller needs
// to report on it.
type LoadResult struct {
	Config   *Config
	Path     string
	Warnings []string
	// Checksum identifies the file contents, so a reload can tell whether anything
	// actually changed.
	Checksum string
	// Created is true when the file did not exist and defaults were used.
	Created bool
}

// Load reads, decodes and validates a configuration file. A missing file is not an
// error: iPulse starts with documented defaults so a fresh install works immediately.
// Unknown keys are rejected, because a silently-ignored typo in a monitoring threshold
// is worse than a refusal to start.
func Load(path string) (*LoadResult, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	cfg := Default()
	res := &LoadResult{Path: path}

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		res.Created = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("configuration file %s not found; using built-in defaults", path))
	case err != nil:
		return nil, fmt.Errorf("read configuration %s: %w", path, err)
	default:
		sum := sha256.Sum256(data)
		res.Checksum = hex.EncodeToString(sum[:8])
		if err := decodeStrict(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse configuration %s: %w", path, err)
		}
	}

	cfg.SetPath(path)
	cfg.ResolvedPaths()
	warns, err := cfg.Validate()
	res.Warnings = append(res.Warnings, warns...)
	res.Config = &cfg
	if err != nil {
		return res, err
	}
	return res, nil
}

// decodeStrict decodes YAML with unknown-field rejection.
func decodeStrict(data []byte, out *Config) error {
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty file means "use all defaults".
			return nil
		}
		return err
	}
	return nil
}

// Parse decodes and validates configuration from memory. Used by tests and by the
// API's configuration-check endpoint.
func Parse(data []byte) (*Config, []string, error) {
	cfg := Default()
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, nil, err
	}
	cfg.ResolvedPaths()
	warns, err := cfg.Validate()
	return &cfg, warns, err
}

// Marshal renders the configuration as YAML. Used by `ipulse config` and by the
// installer when writing the initial file.
func (c *Config) Marshal() ([]byte, error) {
	var buf writeBuffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Redacted returns a copy with secrets removed, safe to expose through the API.
func (c *Config) Redacted() *Config {
	cp := *c
	if cp.Dashboard.AuthToken != "" {
		cp.Dashboard.AuthToken = "***redacted***"
	}
	return &cp
}

// WriteDefault writes a default configuration file if none exists, creating parent
// directories with restrictive permissions. It never overwrites an existing file.
func WriteDefault(path string) (bool, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	cfg := Default()
	data, err := cfg.Marshal()
	if err != nil {
		return false, err
	}
	header := "# iPulse configuration\n# Generated defaults. See docs/configuration.md for every option.\n"
	if err := os.WriteFile(path, append([]byte(header), data...), 0o640); err != nil {
		return false, err
	}
	return true, nil
}
