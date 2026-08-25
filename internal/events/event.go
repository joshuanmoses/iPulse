package events

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/security"
)

// Field is one Key=Value pair in an event body. Order is preserved because the
// human-readable log format is meant to be read top-to-bottom in a stable order.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Render returns the field as it appears in the text log format, quoting the value when
// a space or equals sign would otherwise make Key=Value parsing ambiguous.
func (f Field) Render() string {
	if security.NeedsQuoting(f.Value) {
		return f.Key + `="` + f.Value + `"`
	}
	return f.Key + "=" + f.Value
}

// Fields is an ordered set of event fields.
type Fields []Field

// Add appends a field, formatting the value according to its type and sanitising
// untrusted strings. Nil values are skipped.
func (f Fields) Add(key string, value any) Fields {
	if value == nil {
		return f
	}
	return append(f, Field{Key: security.SanitizeKey(key), Value: formatValue(value)})
}

// AddIf appends the field only when cond is true.
func (f Fields) AddIf(cond bool, key string, value any) Fields {
	if !cond {
		return f
	}
	return f.Add(key, value)
}

// AddUnit appends a numeric field with a unit suffix at one decimal place, which is
// the precision used throughout the documented log format:
// AddUnit("Download", 487.24, "Mbps") renders Download=487.2Mbps.
func (f Fields) AddUnit(key string, value float64, unit string) Fields {
	return f.AddUnitPrec(key, value, unit, 1)
}

// AddUnitPrec appends a numeric field with an explicit decimal precision. Use it for
// values where one decimal is wrong: whole-number percentages (Deviation=305%) or
// small fractions (PacketLoss=0.031%).
func (f Fields) AddUnitPrec(key string, value float64, unit string, prec int) Fields {
	return append(f, Field{
		Key:   security.SanitizeKey(key),
		Value: strconv.FormatFloat(value, 'f', prec, 64) + unit,
	})
}

// AddPercent appends a percentage field with one decimal place (PacketLoss=0.0%).
func (f Fields) AddPercent(key string, value float64) Fields {
	return f.AddUnitPrec(key, value, "%", 1)
}

// AddRatioPercent appends a percentage rendered without decimals, for large
// deviation ratios (Deviation=305%).
func (f Fields) AddRatioPercent(key string, value float64) Fields {
	return f.AddUnitPrec(key, value, "%", 0)
}

// AddRate appends a bit-rate field, choosing bps/Kbps/Mbps/Gbps automatically.
func (f Fields) AddRate(key string, bitsPerSec float64) Fields {
	return append(f, Field{Key: security.SanitizeKey(key), Value: FormatRate(bitsPerSec)})
}

// AddBytes appends a byte-count field with an IEC-style suffix.
func (f Fields) AddBytes(key string, bytes float64) Fields {
	return append(f, Field{Key: security.SanitizeKey(key), Value: FormatBytes(bytes)})
}

// AddDuration appends a duration rendered compactly (12.4s, 186ms).
func (f Fields) AddDuration(key string, d time.Duration) Fields {
	return append(f, Field{Key: security.SanitizeKey(key), Value: FormatDuration(d)})
}

// Get returns the first value for key, and whether it was present.
func (f Fields) Get(key string) (string, bool) {
	for _, fl := range f {
		if strings.EqualFold(fl.Key, key) {
			return fl.Value, true
		}
	}
	return "", false
}

// Map renders the fields as a map for JSON output. Later duplicates win.
func (f Fields) Map() map[string]string {
	m := make(map[string]string, len(f))
	for _, fl := range f {
		m[fl.Key] = fl.Value
	}
	return m
}

// Sorted returns the fields ordered by key; used only where deterministic output
// matters more than readability.
func (f Fields) Sorted() Fields {
	out := make(Fields, len(f))
	copy(out, f)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Event is a single logged decision.
type Event struct {
	// ID is the database row identifier; zero until persisted.
	ID       int64     `json:"id,omitempty"`
	Time     time.Time `json:"time"`
	Code     int       `json:"code"`
	Name     string    `json:"name"`
	Severity Severity  `json:"severity"`
	Category Category  `json:"category"`

	// Message is an optional one-line human summary. The event Name carries the
	// machine meaning, so Message is used sparingly.
	Message string `json:"message,omitempty"`

	// Fields is the ordered structured body.
	Fields Fields `json:"fields,omitempty"`

	// Optional correlation dimensions, promoted out of Fields so they can be indexed.
	Process     string `json:"process,omitempty"`
	Destination string `json:"destination,omitempty"`

	// CorrelationID links events that a correlation rule grouped together.
	CorrelationID string `json:"correlation_id,omitempty"`

	// Suppressed marks an event that a correlation rule absorbed into a higher-level
	// conclusion. Suppressed events are still stored (for forensics) but are not
	// written to the human-readable log sinks.
	Suppressed bool `json:"suppressed,omitempty"`
}

// New builds an event from the catalog definition for code. Unknown codes still
// produce a usable event so a missing catalog entry can never drop telemetry.
func New(code int, fields ...Field) Event {
	def, ok := Lookup(code)
	ev := Event{
		Time:     time.Now(),
		Code:     code,
		Category: CategoryForCode(code),
		Fields:   Fields(fields),
	}
	if ok {
		ev.Name = def.Name
		ev.Severity = def.Severity
		ev.Category = def.Category
	} else {
		ev.Name = "UNCATALOGUED_EVENT_" + strconv.Itoa(code)
		ev.Severity = Info
	}
	return ev
}

// WithSeverity overrides the catalog severity. Used by detectors that escalate (for
// example a warning that becomes an error once it persists).
func (e Event) WithSeverity(s Severity) Event { e.Severity = s; return e }

// WithMessage attaches a sanitised one-line summary.
func (e Event) WithMessage(format string, args ...any) Event {
	e.Message = security.SanitizeSingleLine(fmt.Sprintf(format, args...))
	return e
}

// WithField appends one field.
func (e Event) WithField(key string, value any) Event {
	e.Fields = e.Fields.Add(key, value)
	return e
}

// WithFields appends several fields.
func (e Event) WithFields(f Fields) Event {
	e.Fields = append(e.Fields, f...)
	return e
}

// WithProcess sets the owning process dimension and mirrors it into the body.
func (e Event) WithProcess(name string, pid int) Event {
	e.Process = security.SanitizeSingleLine(name)
	if name != "" {
		e.Fields = e.Fields.Add("Process", name)
	}
	if pid > 0 {
		e.Fields = e.Fields.Add("PID", pid)
	}
	return e
}

// WithDestination sets the remote destination dimension.
func (e Event) WithDestination(dest string) Event {
	e.Destination = security.SanitizeSingleLine(dest)
	return e
}

// WithTime overrides the event timestamp; used by tests and by replayed samples.
func (e Event) WithTime(t time.Time) Event { e.Time = t; return e }

// WithCorrelation stamps a correlation identifier.
func (e Event) WithCorrelation(id string) Event { e.CorrelationID = id; return e }

// Header renders the first log line: timestamp, severity label, event id and name.
func (e Event) Header() string {
	return fmt.Sprintf("%s %s IPULSE-%d %s",
		e.Time.Format(TimeFormat), e.Severity.Label(), e.Code, e.Name)
}

// Text renders the full syslog-style multi-line record.
func (e Event) Text() string {
	var b strings.Builder
	b.WriteString(e.Header())
	if e.Message != "" {
		b.WriteByte('\n')
		b.WriteString(e.Message)
	}
	for _, f := range e.Fields {
		b.WriteByte('\n')
		b.WriteString(f.Render())
	}
	return b.String()
}

// OneLine renders the record on a single line, for terminals and for syslog
// transports that are line-oriented.
func (e Event) OneLine() string {
	var b strings.Builder
	b.WriteString(e.Header())
	if e.Message != "" {
		b.WriteString(" | ")
		b.WriteString(e.Message)
	}
	for i, f := range e.Fields {
		if i == 0 {
			b.WriteString(" | ")
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(f.Render())
	}
	return b.String()
}

// jsonEvent is the JSON Lines wire form. Fields become a flat object because that is
// what log shippers expect.
type jsonEvent struct {
	Time          string            `json:"ts"`
	Severity      string            `json:"severity"`
	Code          int               `json:"event_id"`
	Name          string            `json:"event"`
	Category      string            `json:"category"`
	Message       string            `json:"message,omitempty"`
	Process       string            `json:"process,omitempty"`
	Destination   string            `json:"destination,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Suppressed    bool              `json:"suppressed,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

// JSON renders the event as a single JSON Lines record (no trailing newline).
func (e Event) JSON() ([]byte, error) {
	return json.Marshal(jsonEvent{
		Time:          e.Time.Format(TimeFormat),
		Severity:      e.Severity.String(),
		Code:          e.Code,
		Name:          e.Name,
		Category:      string(e.Category),
		Message:       e.Message,
		Process:       e.Process,
		Destination:   e.Destination,
		CorrelationID: e.CorrelationID,
		Suppressed:    e.Suppressed,
		Fields:        e.Fields.Map(),
	})
}

// TimeFormat is the timestamp layout used across every sink: RFC 3339 with seconds
// and a numeric offset, matching the documented log examples.
const TimeFormat = "2006-01-02T15:04:05-07:00"

func formatValue(v any) string {
	switch t := v.(type) {
	case string:
		return security.SanitizeValue(t)
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float32:
		return trimFloat(float64(t))
	case float64:
		return trimFloat(t)
	case time.Duration:
		return FormatDuration(t)
	case time.Time:
		return t.Format(TimeFormat)
	case error:
		return security.SanitizeValue(t.Error())
	case fmt.Stringer:
		return security.SanitizeValue(t.String())
	default:
		return security.SanitizeValue(fmt.Sprint(v))
	}
}

// trimFloat renders a float with at most one decimal for large magnitudes and up to
// three for small ones, trimming trailing zeros. Log records stay readable without
// losing meaningful precision on values like 0.031 %.
func trimFloat(v float64) string {
	abs := v
	if abs < 0 {
		abs = -abs
	}
	prec := 1
	switch {
	case abs == 0:
		return "0"
	case abs < 0.01:
		prec = 4
	case abs < 1:
		prec = 3
	case abs < 100:
		prec = 2
	}
	s := strconv.FormatFloat(v, 'f', prec, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimSuffix(s, ".")
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

// FormatDuration renders a duration compactly using the unit that keeps 3-4
// significant digits: 1.2ms, 186ms, 12.4s, 4m12s.
func FormatDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "0s"
	case d < 0:
		return "-" + FormatDuration(-d)
	case d < time.Microsecond:
		return strconv.FormatInt(int64(d), 10) + "ns"
	case d < time.Millisecond:
		return trimFloat(float64(d)/float64(time.Microsecond)) + "us"
	case d < time.Second:
		return trimFloat(float64(d)/float64(time.Millisecond)) + "ms"
	case d < time.Minute:
		return trimFloat(d.Seconds()) + "s"
	case d < time.Hour:
		m := int(d / time.Minute)
		s := int((d % time.Minute) / time.Second)
		return strconv.Itoa(m) + "m" + strconv.Itoa(s) + "s"
	default:
		h := int(d / time.Hour)
		m := int((d % time.Hour) / time.Minute)
		return strconv.Itoa(h) + "h" + strconv.Itoa(m) + "m"
	}
}

// FormatRate renders a bit rate with an appropriate unit.
func FormatRate(bitsPerSec float64) string {
	abs := bitsPerSec
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs >= 1e9:
		return strconv.FormatFloat(bitsPerSec/1e9, 'f', 2, 64) + "Gbps"
	case abs >= 1e6:
		return strconv.FormatFloat(bitsPerSec/1e6, 'f', 1, 64) + "Mbps"
	case abs >= 1e3:
		return strconv.FormatFloat(bitsPerSec/1e3, 'f', 1, 64) + "Kbps"
	default:
		return strconv.FormatFloat(bitsPerSec, 'f', 0, 64) + "bps"
	}
}

// FormatBytes renders a byte count with an IEC unit.
func FormatBytes(b float64) string {
	abs := b
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs >= 1<<40:
		return strconv.FormatFloat(b/(1<<40), 'f', 2, 64) + "TiB"
	case abs >= 1<<30:
		return strconv.FormatFloat(b/(1<<30), 'f', 2, 64) + "GiB"
	case abs >= 1<<20:
		return strconv.FormatFloat(b/(1<<20), 'f', 1, 64) + "MiB"
	case abs >= 1<<10:
		return strconv.FormatFloat(b/(1<<10), 'f', 1, 64) + "KiB"
	default:
		return strconv.FormatFloat(b, 'f', 0, 64) + "B"
	}
}
