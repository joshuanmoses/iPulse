//go:build linux

package platform

import "github.com/ipulse/ipulse/internal/platform/linux"

func newProvider() Provider { return linux.New() }
