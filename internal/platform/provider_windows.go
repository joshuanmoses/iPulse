//go:build windows

package platform

import "github.com/ipulse/ipulse/internal/platform/windows"

func newProvider() Provider { return windows.New() }
