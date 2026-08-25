package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration wraps time.Duration so YAML values can be written as "15s", "5m", "30m"
// exactly as they appear in the documented configuration. A bare number is rejected
// rather than silently interpreted as nanoseconds, which is a classic footgun.
type Duration time.Duration

// D returns the wrapped time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String renders the duration in Go syntax.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		var f float64
		if err2 := unmarshal(&f); err2 == nil {
			return fmt.Errorf("duration must include a unit (for example %qs), got bare number %v", strconv.FormatFloat(f, 'f', -1, 64), f)
		}
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("duration is empty")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// MarshalJSON renders the duration as a string so the API is self-describing.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(time.Duration(d).String())), nil
}

// UnmarshalJSON accepts a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
