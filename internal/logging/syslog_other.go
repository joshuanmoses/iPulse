//go:build !linux

package logging

import (
	"fmt"

	"github.com/ipulse/ipulse/internal/events"
)

// newSyslogSink is unavailable off Linux. The caller treats this as "sink disabled".
func newSyslogSink(events.Severity) (Sink, error) {
	return nil, fmt.Errorf("journald/syslog integration is Linux-only: %w", ErrSinkUnsupported)
}
