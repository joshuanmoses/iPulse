package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/connectivity"
	"github.com/ipulse/ipulse/internal/security"
)

func init() {
	register(&command{
		Name:    "diagnostics",
		Summary: "run the layered diagnostic ladder",
		Usage: `ipulse diagnostics [flags]

Run the full diagnostic ladder and report which layer is at fault:

  local device -> network interface -> default gateway -> DNS -> ISP -> Internet

Each layer is tested independently and the evidence is printed, so the conclusion can
be checked rather than taken on trust.

Flags:
  --privileges   print the privilege matrix instead of running tests
  --json         machine-readable output`,
		Run: runDiagnostics,
	})
}

func runDiagnostics(e *env, args []string) error {
	fs := e.flags("diagnostics")
	privileges := fs.Bool("privileges", false, "print the privilege matrix")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	te, err := newTestEnv(e)
	if err != nil {
		return err
	}

	if *privileges {
		return e.printPrivileges(te)
	}

	engine := connectivity.NewEngine(settingsFrom(te.cfg), te.plat, te.lat, te.dns)
	diag := engine.Diagnose(ctx, "cli")
	if e.jsonOut {
		return e.writeJSON(diag)
	}

	fmt.Fprintf(e.out, "\n%s\n\n", e.bold("iPulse Diagnostics"))
	for _, s := range diag.Steps {
		mark := e.green("PASS")
		if !s.OK {
			mark = e.red("FAIL")
		}
		fmt.Fprintf(e.out, "  %s  %-14s %s %s\n", mark, s.Layer, s.Detail,
			e.dim(fmt.Sprintf("(%s)", s.Elapsed.Round(time.Millisecond))))
	}

	verdict := e.green(string(diag.Classification))
	if diag.Classification.IsFailure() {
		verdict = e.red(string(diag.Classification))
	}
	fmt.Fprintf(e.out, "\n  %-16s %s\n", "Conclusion:", verdict)
	fmt.Fprintf(e.out, "  %-16s %s\n", "Probable cause:", diag.ProbableCause)
	fmt.Fprintf(e.out, "  %-16s %s\n\n", "Duration:", diag.Duration.Round(time.Millisecond))
	return nil
}

func (e *env) printPrivileges(te *testEnv) error {
	caps := te.plat.Capabilities()
	report := security.BuildPrivilegeReport(security.Capabilities{
		Platform:           caps.Platform,
		Elevated:           caps.Elevated,
		Interfaces:         caps.Interfaces,
		Routes:             caps.Routes,
		Connections:        caps.Connections,
		ProcessAttribution: caps.ProcessAttribution,
		Wireless:           caps.Wireless,
		ICMP:               caps.ICMP,
		Traceroute:         caps.Traceroute,
		DNSServers:         caps.DNSServers,
	})
	if e.jsonOut {
		return e.writeJSON(report)
	}
	fmt.Fprintf(e.out, "\n%s\n\n", e.bold("iPulse Privileges"))
	e.kv([][2]string{
		{"Platform", report.Platform},
		{"User", report.User},
		{"Elevated", boolWord(e, report.Elevated)},
	})
	fmt.Fprintln(e.out)
	t := e.table()
	t.row("FEATURE", "AVAILABLE", "REQUIRES", "FALLBACK")
	for _, f := range report.Features {
		available := e.green("yes")
		if !f.Available {
			available = e.yellow("no")
		}
		t.row(truncate(f.Feature, 44), available, truncate(f.Required, 40), truncate(f.Fallback, 44))
	}
	t.flush()
	if degraded := report.Degraded(); len(degraded) > 0 {
		fmt.Fprintf(e.out, "\n%s\n", e.yellow("Degraded features:"))
		for _, f := range degraded {
			fmt.Fprintf(e.out, "  - %s\n    needs: %s\n", f.Feature, f.Required)
			if f.Impact != "" {
				fmt.Fprintf(e.out, "    impact: %s\n", f.Impact)
			}
		}
	}
	fmt.Fprintln(e.out)
	return nil
}

var _ = context.Background
