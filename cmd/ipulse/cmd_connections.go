package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

func init() {
	register(&command{
		Name:    "connections",
		Summary: "list observed network connections",
		Usage: `ipulse connections [flags]

List the connections iPulse has observed, most recent first.

Only metadata is recorded: process, endpoints, state and byte counts. No payload is
ever captured.

Flags:
  --since <window>     time window (default 1h)
  --protocol <p>       tcp or udp
  --process <name>     filter by process name
  --remote <ip>        filter by remote address
  --port <n>           filter by remote port
  --state <state>      filter by connection state
  --internal           only connections to private addresses
  --external           only connections to public addresses
  --search <text>      match process, executable or remote address
  --limit <n>          maximum rows (default 50)
  --top                show per-process traffic totals instead of rows
  --json               machine-readable output`,
		Run: runConnections,
	})
}

func runConnections(e *env, args []string) error {
	fs := e.flags("connections")
	since := fs.String("since", "1h", "time window")
	protocol := fs.String("protocol", "", "tcp or udp")
	process := fs.String("process", "", "process filter")
	remote := fs.String("remote", "", "remote address filter")
	port := fs.Int("port", 0, "remote port filter")
	state := fs.String("state", "", "connection state filter")
	internal := fs.Bool("internal", false, "only private destinations")
	external := fs.Bool("external", false, "only public destinations")
	search := fs.String("search", "", "text search")
	limit := fs.Int("limit", 50, "maximum rows")
	top := fs.Bool("top", false, "per-process totals")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	defer e.close()

	window, err := parseWindow(*since)
	if err != nil {
		return fmt.Errorf("invalid --since %q: %w", *since, err)
	}
	db, err := e.database()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	if *top {
		list, err := db.TopProcesses(ctx, time.Now().Add(-window), 20)
		if err != nil {
			return err
		}
		if e.jsonOut {
			return e.writeJSON(list)
		}
		t := e.table()
		t.row("PROCESS", "CONNECTIONS", "SENT", "RECEIVED")
		for _, p := range list {
			t.row(p.Process, fmt.Sprint(p.Connections),
				events.FormatBytes(float64(p.BytesSent)), events.FormatBytes(float64(p.BytesRecv)))
		}
		t.flush()
		return nil
	}

	f := database.ConnectionFilter{
		Since:      time.Now().Add(-window),
		Protocol:   *protocol,
		Process:    *process,
		RemoteIP:   *remote,
		RemotePort: *port,
		State:      *state,
		Search:     *search,
		Limit:      *limit,
	}
	switch {
	case *internal && *external:
		return fmt.Errorf("--internal and --external are mutually exclusive")
	case *internal:
		b := true
		f.Internal = &b
	case *external:
		b := false
		f.Internal = &b
	}

	list, err := db.QueryConnections(ctx, f)
	if err != nil {
		return err
	}
	if e.jsonOut {
		return e.writeJSON(list)
	}
	if len(list) == 0 {
		fmt.Fprintf(e.out, "no connections recorded in the last %s\n", *since)
		return nil
	}
	t := e.table()
	t.row("LAST SEEN", "PROTO", "PROCESS", "PID", "LOCAL", "REMOTE", "STATE", "SENT", "RECV")
	for _, c := range list {
		proc := c.Process
		if proc == "" {
			proc = e.dim("(unknown)")
		}
		t.row(
			c.LastSeen.Format("15:04:05"),
			c.Protocol,
			truncate(proc, 24),
			fmt.Sprint(c.PID),
			endpoint(c.LocalIP, c.LocalPort),
			endpoint(c.RemoteIP, c.RemotePort),
			c.State,
			events.FormatBytes(float64(c.BytesSent)),
			events.FormatBytes(float64(c.BytesRecv)),
		)
	}
	t.flush()
	fmt.Fprintf(e.out, "\n%d connections in the last %s\n", len(list), *since)
	return nil
}

// endpoint renders an address and port, bracketing IPv6 so the port is unambiguous.
func endpoint(ip string, port int) string {
	if ip == "" {
		return fmt.Sprintf("*:%d", port)
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

var _ = strings.TrimSpace
