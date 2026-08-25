// Package logging is the iPulse logging engine.
//
// Design: only Events reach the sinks. Raw measurements go to the database, so the log
// stays a record of decisions rather than a firehose of numbers. Every sink receives
// the same Event, rendered in the form appropriate to that destination:
//
//	ipulse.log    readable syslog-style multi-line records
//	ipulse.jsonl  one JSON object per line, for log shippers
//	events table  searchable history
//	journald      significant events only (Linux)
//	Event Log     significant events only (Windows)
//	stderr        foreground and container mode
package logging

import (
	"errors"

	"github.com/ipulse/ipulse/internal/events"
)

// ErrSinkUnsupported means the sink does not exist on this platform (journald on
// Windows, the Windows Event Log on Linux). Configuration enables both by default so
// one file works everywhere, so this is expected and is not reported as a warning.
var ErrSinkUnsupported = errors.New("sink not supported on this platform")

// Sink is one logging destination.
type Sink interface {
	// Name identifies the sink in error reports.
	Name() string
	// Write emits one event. A sink must not block indefinitely; the logger runs
	// sinks from a single goroutine and a stuck sink would stall logging.
	Write(ev events.Event) error
	// Close flushes and releases resources.
	Close() error
}

// idAssigner is implemented by sinks that assign a persistent identifier to an event
// (the database sink). The logger uses it to publish stored events with their id, which
// is what lets the correlation engine mark contributing events as suppressed later.
type idAssigner interface {
	WriteWithID(ev events.Event) (int64, error)
}

// RotationInfo describes a completed log rotation, so the logger can report it as an
// event without the file sink having to log recursively while holding its own lock.
type RotationInfo struct {
	File             string
	Archive          string
	SizeBytes        int64
	Compressed       bool
	ArchivesRetained int
	ArchivesDeleted  int
}

// rotationReporter is implemented by sinks that rotate files.
type rotationReporter interface {
	takeRotations() []RotationInfo
}
