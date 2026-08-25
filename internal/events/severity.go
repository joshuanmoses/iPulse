// Package events defines the iPulse event model and the authoritative event catalog.
//
// An Event is a decision: something happened that a human might care about. Raw
// numeric observations are Measurements and never reach the log sinks; only Events
// do. That separation is what keeps iPulse from being an alert firehose.
package events

import (
	"fmt"
	"strings"
)

// Severity is the syslog-style importance of an event.
type Severity int

// Severity levels, ordered from least to most severe.
const (
	Debug Severity = iota
	Info
	Notice
	Warning
	Error
	Critical
)

var severityNames = [...]string{"DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"}

// Short log-line labels. Fixed-width-ish labels keep text logs scannable.
var severityShort = [...]string{"DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "CRIT"}

// String returns the canonical name ("WARNING").
func (s Severity) String() string {
	if s < Debug || int(s) >= len(severityNames) {
		return "UNKNOWN"
	}
	return severityNames[s]
}

// Label returns the short form used in text log lines ("WARN").
func (s Severity) Label() string {
	if s < Debug || int(s) >= len(severityShort) {
		return "UNKNOWN"
	}
	return severityShort[s]
}

// Syslog maps the severity onto an RFC 5424 severity code.
func (s Severity) Syslog() int {
	switch s {
	case Debug:
		return 7
	case Info:
		return 6
	case Notice:
		return 5
	case Warning:
		return 4
	case Error:
		return 3
	case Critical:
		return 2
	}
	return 6
}

// MarshalText implements encoding.TextMarshaler so severities serialise as names.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity accepts canonical names, short labels and common aliases,
// case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG", "DBG", "TRACE":
		return Debug, nil
	case "INFO", "INFORMATION", "INFORMATIONAL":
		return Info, nil
	case "NOTICE", "NOTE":
		return Notice, nil
	case "WARN", "WARNING":
		return Warning, nil
	case "ERR", "ERROR":
		return Error, nil
	case "CRIT", "CRITICAL", "FATAL", "ALERT", "EMERG":
		return Critical, nil
	}
	return Info, fmt.Errorf("unknown severity %q", s)
}
