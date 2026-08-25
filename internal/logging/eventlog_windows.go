//go:build windows

package logging

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/version"
)

// eventLogSink forwards significant events to the Windows Event Log under the iPulse
// source. The event ID recorded in the Event Log is the iPulse event code, so a Windows
// administrator can filter on exactly the same identifiers as the iPulse log files.
type eventLogSink struct {
	mu     sync.Mutex
	log    *eventlog.Log
	minSev events.Severity
}

// InstallEventLogSource registers the iPulse event source. It needs Administrator
// rights and is called by the installer, not by the running service.
func InstallEventLogSource() error {
	err := eventlog.InstallAsEventCreate(version.WinServiceName,
		eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil && isAlreadyExists(err) {
		return nil
	}
	return err
}

// RemoveEventLogSource unregisters the event source during uninstall.
func RemoveEventLogSource() error { return eventlog.Remove(version.WinServiceName) }

func isAlreadyExists(err error) bool {
	return err != nil && (contains(err.Error(), "already exists") || contains(err.Error(), "registry key"))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func newEventLogSink(minSev events.Severity) (Sink, error) {
	l, err := eventlog.Open(version.WinServiceName)
	if err != nil {
		return nil, fmt.Errorf("logging: open Windows Event Log source %q: %w (run `ipulse service install` as Administrator to register it)",
			version.WinServiceName, err)
	}
	return &eventLogSink{log: l, minSev: minSev}, nil
}

func (s *eventLogSink) Name() string { return "eventlog" }

func (s *eventLogSink) Write(ev events.Event) error {
	if ev.Severity < s.minSev {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return nil
	}
	// Windows event IDs are unsigned 16-bit in the Event Log API's practical range;
	// iPulse codes are 1000-9999, so they map directly.
	id := uint32(ev.Code)
	msg := ev.Text()
	switch {
	case ev.Severity >= events.Error:
		return s.log.Error(id, msg)
	case ev.Severity >= events.Warning:
		return s.log.Warning(id, msg)
	default:
		return s.log.Info(id, msg)
	}
}

func (s *eventLogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return nil
	}
	err := s.log.Close()
	s.log = nil
	return err
}
