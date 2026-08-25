package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ipulse/ipulse/internal/config"
	"github.com/ipulse/ipulse/internal/security"
	"github.com/ipulse/ipulse/internal/service"
	"github.com/ipulse/ipulse/internal/version"
)

func init() {
	register(&command{
		Name:    "service",
		Summary: "install, remove and control the iPulse service",
		Usage: `ipulse service <subcommand>

Subcommands:
  run           run the agent under the platform service supervisor
  unit          print the systemd unit file that install would write
  install       register the service and start it
  uninstall     stop and remove the service
  start         start the service
  stop          stop the service
  restart       restart the service
  status        report the service state

Install flags:
  --user <name>     account to run as (Linux; default: ipulse)
  --no-enable       do not start the service at boot
  --no-start        do not start the service now

Uninstall flags:
  --purge           also delete the database and logs
  --keep-data       keep the database and logs (default)`,
		Run: runService,
	})

	// Convenience aliases, as documented in the command reference.
	for _, alias := range []struct{ name, sub, summary string }{
		{"start", "start", "start the iPulse service"},
		{"stop", "stop", "stop the iPulse service"},
		{"restart", "restart", "restart the iPulse service"},
	} {
		a := alias
		register(&command{
			Name:    a.name,
			Summary: a.summary,
			Usage:   "ipulse " + a.name + "\n\nEquivalent to `ipulse service " + a.sub + "`.",
			Run: func(e *env, args []string) error {
				return runService(e, append([]string{a.sub}, args...))
			},
		})
	}
}

func runService(e *env, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	sub, rest := args[0], args[1:]
	mgr := service.NewManager()

	switch sub {
	case "run":
		return runAgent(e, rest, true)

	case "unit":
		fs := e.flags("service unit")
		user := fs.String("user", version.LinuxServiceName, "account the unit runs as")
		exec := fs.String("exec", "/usr/bin/ipulse", "installed binary path")
		if err := e.parse(fs, rest); err != nil {
			return err
		}
		cfgPath := e.configPath
		if cfgPath == "" {
			cfgPath = config.DefaultConfigPath()
		}
		unit, err := service.UnitFileContents(*exec, service.InstallOptions{
			ConfigPath: cfgPath,
			User:       *user,
			DataDir:    config.SystemDataDir(),
			LogDir:     config.SystemLogDir(),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(e.out, unit)
		return err

	case "install":
		fs := e.flags("service install")
		user := fs.String("user", version.LinuxServiceName, "account to run the service as")
		noEnable := fs.Bool("no-enable", false, "do not enable at boot")
		noStart := fs.Bool("no-start", false, "do not start now")
		if err := e.parse(fs, rest); err != nil {
			return err
		}
		if ok, why := mgr.Supported(); !ok {
			return fmt.Errorf("%s", why)
		}
		if !security.IsElevated() {
			return fmt.Errorf("installing the service requires administrative privileges")
		}
		cfgPath := e.configPath
		if cfgPath == "" {
			cfgPath = config.DefaultConfigPath()
		}
		if _, err := config.WriteDefault(cfgPath); err != nil {
			return fmt.Errorf("create default configuration: %w", err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		for _, dir := range []string{cfg.Config.Service.DataDir, cfg.Config.Service.LogDir} {
			if err := security.EnsureDir(dir, security.DirMode); err != nil {
				return err
			}
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if err := mgr.Install(service.InstallOptions{
			ExecPath:   exe,
			ConfigPath: cfgPath,
			User:       *user,
			DataDir:    cfg.Config.Service.DataDir,
			LogDir:     cfg.Config.Service.LogDir,
			Enable:     !*noEnable,
			Start:      !*noStart,
		}); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s installed\n", mgr.Name())
		fmt.Fprintf(e.out, "  config:   %s\n", cfgPath)
		fmt.Fprintf(e.out, "  data:     %s\n", cfg.Config.Service.DataDir)
		fmt.Fprintf(e.out, "  logs:     %s\n", cfg.Config.Service.LogDir)
		if cfg.Config.Dashboard.Enabled {
			fmt.Fprintf(e.out, "  dashboard: http://%s:%d\n", cfg.Config.Dashboard.Address, cfg.Config.Dashboard.Port)
		}
		return nil

	case "uninstall", "remove":
		fs := e.flags("service uninstall")
		purge := fs.Bool("purge", false, "delete the database and logs")
		keep := fs.Bool("keep-data", true, "keep the database and logs")
		if err := e.parse(fs, rest); err != nil {
			return err
		}
		if !security.IsElevated() {
			return fmt.Errorf("removing the service requires administrative privileges")
		}
		keepData := *keep && !*purge
		cfgPath := e.configPath
		if cfgPath == "" {
			cfgPath = config.DefaultConfigPath()
		}
		opts := service.UninstallOptions{KeepData: keepData, ConfigDir: filepath.Dir(cfgPath)}
		if res, err := config.Load(cfgPath); err == nil {
			opts.DataDir = res.Config.Service.DataDir
			opts.LogDir = res.Config.Service.LogDir
		} else {
			opts.DataDir = config.DefaultDataDir()
			opts.LogDir = config.DefaultLogDir()
		}
		if err := mgr.Uninstall(opts); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s removed\n", mgr.Name())
		if keepData {
			fmt.Fprintf(e.out, "historical data kept in %s and %s\n", opts.DataDir, opts.LogDir)
			fmt.Fprintln(e.out, "re-run with --purge to delete it")
		} else {
			fmt.Fprintln(e.out, "database and logs deleted")
		}
		return nil

	case "start":
		if err := mgr.Start(); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s started\n", mgr.Name())
		return nil

	case "stop":
		if err := mgr.Stop(); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s stopped\n", mgr.Name())
		return nil

	case "restart":
		if err := mgr.Restart(); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s restarted\n", mgr.Name())
		return nil

	case "status":
		st, err := mgr.Status()
		if err != nil {
			return err
		}
		if e.jsonOut {
			return e.writeJSON(st)
		}
		pairs := [][2]string{
			{"Service", st.Name},
			{"Installed", fmt.Sprint(st.Installed)},
			{"State", string(st.State)},
		}
		if st.PID > 0 {
			pairs = append(pairs, [2]string{"PID", fmt.Sprint(st.PID)})
		}
		if st.StartType != "" {
			pairs = append(pairs, [2]string{"Start type", st.StartType})
		}
		if st.Detail != "" {
			pairs = append(pairs, [2]string{"Detail", st.Detail})
		}
		e.kv(pairs)
		return nil

	default:
		return errUsage
	}
}
