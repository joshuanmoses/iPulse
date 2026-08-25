package main

import (
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

func init() {
	register(&command{
		Name:    "destinations",
		Summary: "list remote destinations and their history",
		Usage: `ipulse destinations [flags]

List the remote endpoints this host has contacted, with first/last seen, contact
frequency, traffic volume and any network enrichment.

Flags:
  --since <window>   time window (default 7d)
  --new <window>     only destinations first seen within this window
  --order <field>    last_seen (default), contacts, bytes_sent, first_seen
  --flagged          only destinations matched by threat intelligence
  --internal         only private-range destinations
  --search <text>    match address, reverse DNS, organisation or process
  --limit <n>        maximum rows (default 50)
  --json             machine-readable output

Examples:
  ipulse destinations --order bytes_sent
  ipulse destinations --new 24h
  ipulse destinations --flagged`,
		Run: runDestinations,
	})
}

func runDestinations(e *env, args []string) error {
	fs := e.flags("destinations")
	since := fs.String("since", "7d", "time window")
	newWindow := fs.String("new", "", "only destinations first seen within this window")
	order := fs.String("order", "last_seen", "sort order")
	flagged := fs.Bool("flagged", false, "only threat-intelligence matches")
	internal := fs.Bool("internal", false, "only private destinations")
	search := fs.String("search", "", "text search")
	limit := fs.Int("limit", 50, "maximum rows")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	defer e.close()

	window, err := parseWindow(*since)
	if err != nil {
		return fmt.Errorf("invalid --since %q: %w", *since, err)
	}
	f := database.DestinationFilter{
		Since:   time.Now().Add(-window),
		OrderBy: *order,
		Search:  *search,
		Limit:   *limit,
	}
	if *newWindow != "" {
		nw, err := parseWindow(*newWindow)
		if err != nil {
			return fmt.Errorf("invalid --new %q: %w", *newWindow, err)
		}
		f.NewSince = time.Now().Add(-nw)
	}
	if *flagged {
		b := true
		f.Flagged = &b
	}
	if *internal {
		b := true
		f.Internal = &b
	}

	db, err := e.database()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	list, err := db.QueryDestinations(ctx, f)
	if err != nil {
		return err
	}
	if e.jsonOut {
		return e.writeJSON(list)
	}
	if len(list) == 0 {
		fmt.Fprintln(e.out, "no destinations recorded for that filter")
		return nil
	}
	t := e.table()
	t.row("DESTINATION", "PROTO", "CONTACTS", "SENT", "RECV", "FIRST SEEN", "LAST SEEN", "ORG", "COUNTRY")
	for _, d := range list {
		dest := endpoint(d.RemoteIP, d.RemotePort)
		if d.ReverseDNS != "" {
			dest = fmt.Sprintf("%s (%s)", dest, truncate(d.ReverseDNS, 28))
		}
		if d.Flagged {
			dest = e.red("! ") + dest
		}
		t.row(
			dest,
			d.Protocol,
			fmt.Sprint(d.Contacts),
			events.FormatBytes(float64(d.BytesSent)),
			events.FormatBytes(float64(d.BytesRecv)),
			humanAge(d.FirstSeen),
			humanAge(d.LastSeen),
			truncate(d.ASNOrg, 24),
			d.Country,
		)
	}
	t.flush()
	total, _ := db.DestinationCount(ctx)
	fmt.Fprintf(e.out, "\n%d shown, %d known destinations in total\n", len(list), total)
	return nil
}
