//go:build !windows

package logging

import (
	"fmt"

	"github.com/ipulse/ipulse/internal/events"
)

// newEventLogSink is unavailable off Windows. The caller treats this as "sink disabled".
func newEventLogSink(events.Severity) (Sink, error) {
	return nil, fmt.Errorf("Windows Event Log integration is Windows-only: %w", ErrSinkUnsupported)
}

// InstallEventLogSource is a no-op off Windows.
func InstallEventLogSource() error { return nil }

// RemoveEventLogSource is a no-op off Windows.
func RemoveEventLogSource() error { return nil }
