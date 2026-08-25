// Command ipulse is the iPulse agent and its command-line interface.
//
// The same binary serves three roles:
//
//	ipulse run              foreground agent (development, containers, portable mode)
//	ipulse service run      agent under systemd or the Windows Service Control Manager
//	ipulse <verb>           command-line client
//
// Client commands read the local database directly (read-only) or run a probe in
// process, so they work whether or not the service is running.
package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ipulse/ipulse/internal/version"
)

// command is one CLI verb.
type command struct {
	Name    string
	Summary string
	// Usage is the full help text, printed by `ipulse help <name>`.
	Usage string
	Run   func(env *env, args []string) error
	// Hidden keeps aliases out of the command list.
	Hidden bool
}

var commands []*command

func register(c *command) { commands = append(commands, c) }

func lookup(name string) *command {
	for _, c := range commands {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	env := newEnv()

	// Global flags may appear before the verb.
	rest, err := env.parseGlobal(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ipulse: %v\n", err)
		return 2
	}
	if len(rest) == 0 {
		usage(env)
		return 0
	}

	name := rest[0]
	switch name {
	case "help", "-h", "--help":
		if len(rest) > 1 {
			if c := lookup(rest[1]); c != nil {
				fmt.Fprintln(env.out, strings.TrimSpace(c.Usage))
				return 0
			}
			fmt.Fprintf(os.Stderr, "ipulse: unknown command %q\n", rest[1])
			return 2
		}
		usage(env)
		return 0
	case "-v", "--version":
		name = "version"
	}

	c := lookup(name)
	if c == nil {
		fmt.Fprintf(os.Stderr, "ipulse: unknown command %q\nRun 'ipulse help' for usage.\n", name)
		return 2
	}
	if err := c.Run(env, rest[1:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(c.Usage))
			return 2
		}
		fmt.Fprintf(os.Stderr, "ipulse %s: %v\n", c.Name, err)
		return 1
	}
	return 0
}

// errUsage signals that the command was invoked incorrectly and its usage should print.
var errUsage = errors.New("invalid usage")

func usage(env *env) {
	w := env.out
	fmt.Fprintf(w, "%s - %s\n\n", version.Product, version.Description)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  ipulse [global flags] <command> [flags]")
	fmt.Fprintln(w, "\nCommands:")

	visible := make([]*command, 0, len(commands))
	for _, c := range commands {
		if !c.Hidden {
			visible = append(visible, c)
		}
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].Name < visible[j].Name })
	for _, c := range visible {
		fmt.Fprintf(w, "  %-14s %s\n", c.Name, c.Summary)
	}
	fmt.Fprintln(w, "\nGlobal flags:")
	fmt.Fprintln(w, "  --config <path>  configuration file (default: platform location)")
	fmt.Fprintln(w, "  --json           machine-readable JSON output where supported")
	fmt.Fprintln(w, "  --no-color       disable colour output")
	fmt.Fprintln(w, "\nRun 'ipulse help <command>' for details.")
}
