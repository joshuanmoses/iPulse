package main

import (
	"fmt"
	"os"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/security"
)

func init() {
	register(&command{
		Name:    "config",
		Summary: "show, validate or generate configuration",
		Usage: `ipulse config [subcommand]

Subcommands:
  (none)      print the effective configuration, with secrets redacted
  validate    validate the configuration file and report every problem
  default     print the built-in default configuration
  path        print the configuration, data and log locations
  init        write a default configuration file if none exists

Flags:
  --config <path>   configuration file to use
  --json            JSON output (for the default subcommand: still YAML)`,
		Run: runConfig,
	})
}

func runConfig(e *env, args []string) error {
	sub := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	fs := e.flags("config")
	if err := e.parse(fs, args); err != nil {
		return err
	}

	switch sub {
	case "", "show":
		cfg, err := e.config()
		if err != nil {
			return err
		}
		if e.jsonOut {
			return e.writeJSON(cfg.Redacted())
		}
		data, err := cfg.Redacted().Marshal()
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "# effective configuration (source: %s)\n", cfg.Path())
		_, err = e.out.Write(data)
		return err

	case "validate":
		path := e.configPath
		if path == "" {
			path = config.DefaultConfigPath()
		}
		res, err := config.Load(path)
		if err != nil {
			fmt.Fprintf(e.out, "%s %s\n", e.red("INVALID"), path)
			fmt.Fprintln(e.out, err)
			return fmt.Errorf("configuration is not valid")
		}
		fmt.Fprintf(e.out, "%s %s\n", e.green("VALID"), res.Path)
		if res.Created {
			fmt.Fprintln(e.out, "note: the file does not exist; built-in defaults were validated instead")
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(e.out, "%s %s\n", e.yellow("warning:"), w)
		}
		for _, w := range security.AuditPaths(res.Path, res.Config.Service.DataDir, res.Config.Service.LogDir) {
			fmt.Fprintf(e.out, "%s %s\n", e.yellow("warning:"), w)
		}
		return nil

	case "default":
		def := config.Default()
		def.ResolvedPaths()
		data, err := def.Marshal()
		if err != nil {
			return err
		}
		_, err = e.out.Write(data)
		return err

	case "path":
		cfg, err := e.config()
		if err != nil {
			// Still useful to print the locations even when the file is invalid.
			e.kv([][2]string{
				{"Config", config.DefaultConfigPath()},
				{"Data", config.DefaultDataDir()},
				{"Logs", config.DefaultLogDir()},
			})
			return err
		}
		pairs := [][2]string{
			{"Config", cfg.Path()},
			{"Data", cfg.Service.DataDir},
			{"Logs", cfg.Service.LogDir},
			{"Database", cfg.Database.Path},
		}
		if root := config.PortableRoot(); root != "" {
			pairs = append(pairs, [2]string{"Portable root", root})
		}
		e.kv(pairs)
		return nil

	case "init":
		path := e.configPath
		if path == "" {
			path = config.DefaultConfigPath()
		}
		created, err := config.WriteDefault(path)
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintf(e.out, "wrote default configuration to %s\n", path)
		} else {
			fmt.Fprintf(e.out, "%s already exists; not modified\n", path)
		}
		return nil

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		return errUsage
	}
}
