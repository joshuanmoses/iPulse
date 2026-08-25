package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/database"
)

// env carries process-wide options and lazily-opened resources for CLI commands.
type env struct {
	out        io.Writer
	errOut     io.Writer
	configPath string
	jsonOut    bool
	noColor    bool

	cfg *config.Config
	db  *database.DB
}

func newEnv() *env {
	return &env{
		out:     os.Stdout,
		errOut:  os.Stderr,
		noColor: os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout),
	}
}

// parseGlobal consumes global flags that appear before the verb.
func (e *env) parseGlobal(args []string) ([]string, error) {
	for len(args) > 0 {
		switch {
		case args[0] == "--config" || args[0] == "-c":
			if len(args) < 2 {
				return nil, errors.New("--config requires a path")
			}
			e.configPath = args[1]
			args = args[2:]
		case strings.HasPrefix(args[0], "--config="):
			e.configPath = strings.TrimPrefix(args[0], "--config=")
			args = args[1:]
		case args[0] == "--json":
			e.jsonOut = true
			args = args[1:]
		case args[0] == "--no-color":
			e.noColor = true
			args = args[1:]
		default:
			return args, nil
		}
	}
	return nil, nil
}

// flags builds a flag set that also accepts the global flags, so `ipulse events --json`
// works as naturally as `ipulse --json events`.
func (e *env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("ipulse "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&e.configPath, "config", e.configPath, "configuration file")
	fs.BoolVar(&e.jsonOut, "json", e.jsonOut, "JSON output")
	fs.BoolVar(&e.noColor, "no-color", e.noColor, "disable colour")
	return fs
}

// parse runs a flag set, translating a flag error into a usage error.
func (e *env) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errUsage
		}
		return fmt.Errorf("%v", err)
	}
	return nil
}

// config loads and validates the configuration, caching the result.
func (e *env) config() (*config.Config, error) {
	if e.cfg != nil {
		return e.cfg, nil
	}
	res, err := config.Load(e.configPath)
	if err != nil {
		// A configuration that fails validation must not be silently replaced with
		// defaults for a client command: the operator needs to know.
		return nil, err
	}
	e.cfg = res.Config
	return e.cfg, nil
}

// database opens the local database read-only. Client commands never write to it, so a
// running agent is never disturbed.
func (e *env) database() (*database.DB, error) {
	if e.db != nil {
		return e.db, nil
	}
	cfg, err := e.config()
	if err != nil {
		return nil, err
	}
	db, err := database.Open(database.Options{
		Path:        cfg.Database.Path,
		BusyTimeout: cfg.Database.BusyTimeout.D(),
		ReadOnly:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("%w\n\nThe database is created when the agent first runs. "+
			"Start it with `ipulse start`, or run `ipulse run` in the foreground.", err)
	}
	e.db = db
	return db, nil
}

func (e *env) close() {
	if e.db != nil {
		_ = e.db.Close()
		e.db = nil
	}
}

// signalContext returns a context cancelled by Ctrl-C, for long-running client commands.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
