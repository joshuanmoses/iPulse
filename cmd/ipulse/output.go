package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ipulse/ipulse/internal/events"
)

// ANSI colours, used only when the output is a terminal and colour is not disabled.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
)

func (e *env) color(code, s string) string {
	if e.noColor {
		return s
	}
	return code + s + ansiReset
}

func (e *env) bold(s string) string   { return e.color(ansiBold, s) }
func (e *env) dim(s string) string    { return e.color(ansiDim, s) }
func (e *env) green(s string) string  { return e.color(ansiGreen, s) }
func (e *env) red(s string) string    { return e.color(ansiRed, s) }
func (e *env) yellow(s string) string { return e.color(ansiYellow, s) }
func (e *env) cyan(s string) string   { return e.color(ansiCyan, s) }

// severityColor renders a severity label in its conventional colour.
func (e *env) severityColor(s events.Severity) string {
	label := s.Label()
	switch s {
	case events.Debug:
		return e.dim(label)
	case events.Info:
		return label
	case events.Notice:
		return e.color(ansiBlue, label)
	case events.Warning:
		return e.yellow(label)
	case events.Error, events.Critical:
		return e.red(label)
	}
	return label
}

// writeJSON prints a value as indented JSON.
func (e *env) writeJSON(v any) error {
	enc := json.NewEncoder(e.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table is a small aligned-column writer.
type table struct {
	w *tabwriter.Writer
}

func (e *env) table() *table {
	return &table{w: tabwriter.NewWriter(e.out, 0, 4, 2, ' ', 0)}
}

func (t *table) row(cells ...string) {
	fmt.Fprintln(t.w, strings.Join(cells, "\t"))
}

func (t *table) flush() { _ = t.w.Flush() }

// kv prints an aligned key/value block, the format used by `ipulse status`.
func (e *env) kv(pairs [][2]string) {
	width := 0
	for _, p := range pairs {
		if len(p[0]) > width {
			width = len(p[0])
		}
	}
	for _, p := range pairs {
		fmt.Fprintf(e.out, "%-*s %s\n", width+1, p[0]+":", p[1])
	}
}

// humanAge renders a timestamp as a relative age, the way an operator reads it.
func humanAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		return "just now"
	}
	switch {
	case d < 2*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < 2*time.Minute:
		return "1 minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 2*time.Hour:
		return "1 hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// isTerminal reports whether w is a character device, so colour is only used when a
// human is watching.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
