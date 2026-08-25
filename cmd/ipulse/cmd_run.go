package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/ipulse/ipulse/internal/agent"
	"github.com/ipulse/ipulse/internal/api"
	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/service"
)

func init() {
	register(&command{
		Name:    "run",
		Summary: "run the agent in the foreground",
		Usage: `ipulse run [flags]

Run the iPulse agent in the foreground. Useful for development, for containers, and for
portable mode. Logging to stderr is enabled automatically.

Flags:
  --config <path>   configuration file
  --quiet           do not mirror events to stderr
  --portable <dir>  use <dir> for configuration, data and logs

Signals:
  SIGINT, SIGTERM   graceful shutdown
  SIGHUP            reload configuration (Linux)`,
		Run: func(e *env, args []string) error { return runAgent(e, args, false) },
	})
}

// runAgent starts the agent. asService selects the platform service supervisor path;
// foreground runs mirror events to stderr.
func runAgent(e *env, args []string, asService bool) error {
	name := "run"
	if asService {
		name = "service run"
	}
	fs := e.flags(name)
	quiet := fs.Bool("quiet", false, "do not mirror events to stderr")
	portable := fs.String("portable", "", "run in portable mode from this directory")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	if *portable != "" {
		// Portable mode is expressed as an environment variable so every path helper
		// picks it up, including those used before the configuration is loaded.
		if err := os.Setenv(config.EnvHome, *portable); err != nil {
			return err
		}
	}

	res, err := config.Load(e.configPath)
	if err != nil {
		return err
	}
	cfg := res.Config

	a, err := agent.New(agent.Options{
		Config:         cfg,
		ConfigWarnings: res.Warnings,
		ConfigChecksum: res.Checksum,
		Mode:           map[bool]string{true: "service", false: "foreground"}[asService],
		ForceConsole:   !asService && !*quiet,
	})
	if err != nil {
		return err
	}

	if cfg.Dashboard.Enabled {
		srv, err := api.New(api.Options{
			Config:  cfg,
			Backend: a,
			Logger:  a.Logger(),
		})
		if err != nil {
			return err
		}
		a.SetServer(srv)
	}

	if !asService {
		for _, w := range res.Warnings {
			fmt.Fprintf(e.errOut, "warning: %s\n", w)
		}
		if cfg.Dashboard.Enabled {
			fmt.Fprintf(e.errOut, "dashboard: http://%s:%d\n", cfg.Dashboard.Address, cfg.Dashboard.Port)
		}
	}

	// SIGHUP triggers a configuration reload without a restart.
	hup := make(chan os.Signal, 1)
	registerReloadSignal(hup)
	go func() {
		for range hup {
			a.Reload()
		}
	}()
	defer signal.Stop(hup)

	_, runErr := service.Run(func(ctx context.Context, ready func()) error {
		return a.Run(ctx, ready)
	})
	return runErr
}
