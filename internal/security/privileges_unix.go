//go:build !windows

package security

import "os"

func isElevated() bool { return os.Geteuid() == 0 }
