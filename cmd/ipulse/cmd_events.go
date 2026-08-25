package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

func init() {
	register(&command{
		Name:    "events",
		Summary: "browse the syslog-style event log",
		Usage: `ipulse events [flags]

Show recorded events, newest first, in the same format as the log files.

Flags:
  --severity <level>   minimum severity: debug, info, notice, warning, error, critical
  --exact              treat --severity as an exact level rather than a minimum
  --code <n[,n...]>    filter by event ID
  --name <n[,n...]>    filter by event name
  --category <c[,c]>   filter by category (connectivity, performance, availability,
                       traffic, security, dns_routing, interface, service, internal)
  --process <name>     filter by process
  --destination <ip>   filter by destination
  --search <text>      free-text search across the rendered record
  --since <window>     time window: 30m, 24h, 7d, 1w (default 24h)
  --limit <n>          maximum records (default 50)
  --follow, -f         stream new events as they are recorded
  --oneline            one line per event
  --suppressed         include events absorbed by a correlation rule
  --stats              print a severity summary instead of records
  --json               machine-readable output

Examples:
  ipulse events --severity warning
  ipulse events --category security --since 7d
  ipulse events --code 3001,3004 --oneline
  ipulse events -f

Subcommands:
  catalog              list every event iPulse can emit
  catalog --code <n>   explain one event ID
  catalog --markdown   regenerate docs/event-catalog.md`,
		Run: runEvents,
	})
}

func runEvents(e *env, args []string) error {
	// `ipulse events catalog` prints the event catalog rather than recorded events.
	if len(args) > 0 && args[0] == "catalog" {
		return runEventCatalog(e, args[1:])
	}
	fs := e.flags("events")
	severity := fs.String("severity", "", "minimum severity")
	exact := fs.Bool("exact", false, "exact severity match")
	codes := fs.String("code", "", "event IDs")
	names := fs.String("name", "", "event names")
	categories := fs.String("category", "", "categories")
	process := fs.String("process", "", "process filter")
	destination := fs.String("destination", "", "destination filter")
	search := fs.String("search", "", "text search")
	since := fs.String("since", "24h", "time window")
	limit := fs.Int("limit", 50, "maximum records")
	follow := fs.Bool("follow", false, "stream new events")
	followShort := fs.Bool("f", false, "stream new events")
	oneline := fs.Bool("oneline", false, "one line per event")
	suppressed := fs.Bool("suppressed", false, "include suppressed events")
	stats := fs.Bool("stats", false, "severity summary")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	defer e.close()

	window, err := parseWindow(*since)
	if err != nil {
		return fmt.Errorf("invalid --since %q: %w", *since, err)
	}
	f := database.EventFilter{
		Since:             time.Now().Add(-window),
		Process:           *process,
		Destination:       *destination,
		Search:            *search,
		Limit:             *limit,
		IncludeSuppressed: *suppressed,
	}
	if *severity != "" {
		sev, err := events.ParseSeverity(*severity)
		if err != nil {
			return err
		}
		if *exact {
			f.Severity = &sev
		} else {
			f.MinSeverity = &sev
		}
	}
	for _, raw := range splitList(*codes) {
		code, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid --code %q: event IDs are numeric", raw)
		}
		f.Codes = append(f.Codes, code)
	}
	f.Names = splitList(*names)
	f.Categories = splitList(*categories)

	db, err := e.database()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	if *stats {
		counts, err := db.SeverityCounts(ctx, f.Since)
		if err != nil {
			return err
		}
		top, err := db.TopEventCodes(ctx, f.Since, 15)
		if err != nil {
			return err
		}
		if e.jsonOut {
			byName := map[string]int64{}
			for k, v := range counts {
				byName[k.String()] = v
			}
			return e.writeJSON(map[string]any{"by_severity": byName, "top": top})
		}
		fmt.Fprintf(e.out, "Events in the last %s\n\n", *since)
		for _, sev := range []events.Severity{events.Critical, events.Error, events.Warning,
			events.Notice, events.Info, events.Debug} {
			if n, ok := counts[sev]; ok {
				fmt.Fprintf(e.out, "  %-8s %d\n", e.severityColor(sev), n)
			}
		}
		if len(top) > 0 {
			fmt.Fprintln(e.out, "\nMost frequent:")
			t := e.table()
			t.row("EVENT", "ID", "SEVERITY", "COUNT")
			for _, ec := range top {
				t.row(ec.Name, fmt.Sprintf("IPULSE-%d", ec.Code), ec.Severity.Label(), fmt.Sprint(ec.Count))
			}
			t.flush()
		}
		return nil
	}

	list, err := db.QueryEvents(ctx, f)
	if err != nil {
		return err
	}
	if e.jsonOut {
		return e.writeJSON(list)
	}
	// Oldest first reads like a log file.
	for i := len(list) - 1; i >= 0; i-- {
		e.printEvent(list[i], *oneline)
	}
	if len(list) == 0 {
		fmt.Fprintf(e.out, "no events in the last %s\n", *since)
	}

	if *follow || *followShort {
		return e.followEvents(ctx, db, f, *oneline, lastID(list))
	}
	return nil
}

func lastID(list []database.StoredEvent) int64 {
	var max int64
	for _, ev := range list {
		if ev.ID > max {
			max = ev.ID
		}
	}
	return max
}

// followEvents polls for new records. Polling the database keeps `ipulse events -f`
// working without a connection to the agent, and a 1 s interval is imperceptible.
func (e *env) followEvents(ctx context.Context, db *database.DB, f database.EventFilter, oneline bool, lastSeen int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(e.out)
			return nil
		case <-ticker.C:
			f.Since = time.Now().Add(-1 * time.Minute)
			f.Limit = 200
			list, err := db.QueryEvents(ctx, f)
			if err != nil {
				return err
			}
			for i := len(list) - 1; i >= 0; i-- {
				if list[i].ID <= lastSeen {
					continue
				}
				e.printEvent(list[i], oneline)
				if list[i].ID > lastSeen {
					lastSeen = list[i].ID
				}
			}
		}
	}
}

// printEvent renders a stored event in the log format, with the severity coloured.
func (e *env) printEvent(ev database.StoredEvent, oneline bool) {
	header := fmt.Sprintf("%s %s IPULSE-%d %s",
		ev.Time.Format(events.TimeFormat), e.severityColor(ev.Severity), ev.Code, e.bold(ev.Name))
	if oneline {
		var parts []string
		if ev.Message != "" {
			parts = append(parts, ev.Message)
		}
		// The rendered form preserves field order; reuse it for the one-line view.
		if body := renderedBody(ev.Rendered); body != "" {
			parts = append(parts, body)
		}
		if len(parts) > 0 {
			fmt.Fprintf(e.out, "%s | %s\n", header, strings.Join(parts, " "))
			return
		}
		fmt.Fprintln(e.out, header)
		return
	}
	fmt.Fprintln(e.out, header)
	if ev.Message != "" {
		fmt.Fprintln(e.out, ev.Message)
	}
	// The stored record keeps the canonical field order and is already sanitised, so
	// its body is printed verbatim.
	if lines := strings.Split(ev.Rendered, "\n"); len(lines) > 1 {
		for _, l := range lines[1:] {
			if l != "" {
				fmt.Fprintln(e.out, l)
			}
		}
	}
	fmt.Fprintln(e.out)
}

// renderedBody returns everything after the header line of a stored record.
func renderedBody(rendered string) string {
	i := strings.IndexByte(rendered, '\n')
	if i < 0 {
		return ""
	}
	return strings.ReplaceAll(strings.TrimSpace(rendered[i+1:]), "\n", " ")
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseWindow accepts Go durations plus d/w/m/y suffixes.
func parseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 24 * time.Hour, nil
	}
	units := []struct {
		suffix string
		mult   time.Duration
	}{
		{"d", 24 * time.Hour},
		{"w", 7 * 24 * time.Hour},
		{"mo", 30 * 24 * time.Hour},
		{"y", 365 * 24 * time.Hour},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			if err != nil {
				continue
			}
			if n <= 0 {
				return 0, fmt.Errorf("window must be positive")
			}
			return time.Duration(n * float64(u.mult)), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("window must be positive")
	}
	return d, nil
}

// runEventCatalog prints the event catalog. The markdown form generates
// docs/event-catalog.md, so the documentation cannot drift from the code.
func runEventCatalog(e *env, args []string) error {
	fs := e.flags("events catalog")
	markdown := fs.Bool("markdown", false, "render the catalog as markdown")
	code := fs.Int("code", 0, "explain a single event ID")
	if err := e.parse(fs, args); err != nil {
		return err
	}

	if *code != 0 {
		def, ok := events.Lookup(*code)
		if !ok {
			return fmt.Errorf("no event with ID %d", *code)
		}
		if e.jsonOut {
			return e.writeJSON(def)
		}
		fmt.Fprintf(e.out, "\n%s IPULSE-%d %s\n\n", e.severityColor(def.Severity), def.Code, e.bold(def.Name))
		e.kv([][2]string{
			{"Severity", def.Severity.String()},
			{"Category", string(def.Category)},
			{"Meaning", def.Summary},
			{"Trigger", def.Trigger},
			{"Fields", strings.Join(def.Fields, ", ")},
			{"Action", def.Action},
		})
		fmt.Fprintln(e.out)
		return nil
	}

	if *markdown {
		_, err := fmt.Fprint(e.out, events.Markdown())
		return err
	}
	if e.jsonOut {
		return e.writeJSON(events.All())
	}
	t := e.table()
	t.row("ID", "EVENT", "SEVERITY", "CATEGORY", "MEANING")
	for _, def := range events.All() {
		t.row(fmt.Sprintf("IPULSE-%d", def.Code), def.Name, def.Severity.Label(),
			string(def.Category), truncate(def.Summary, 58))
	}
	t.flush()
	fmt.Fprintf(e.out, "\n%d events. Use --markdown to regenerate docs/event-catalog.md.\n", len(events.All()))
	return nil
}
