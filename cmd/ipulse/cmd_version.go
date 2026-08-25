package main

import (
	"fmt"
	"runtime"

	"github.com/ipulse/ipulse/internal/version"
)

func init() {
	register(&command{
		Name:    "version",
		Summary: "print version and build information",
		Usage: `ipulse version

Print the iPulse version, build metadata and Go runtime.

Flags:
  --json   machine-readable output`,
		Run: func(e *env, args []string) error {
			fs := e.flags("version")
			if err := e.parse(fs, args); err != nil {
				return err
			}
			if e.jsonOut {
				return e.writeJSON(map[string]string{
					"product":    version.Product,
					"version":    version.Version,
					"commit":     version.Commit,
					"build_date": version.BuildDate,
					"platform":   version.Platform(),
					"go":         runtime.Version(),
				})
			}
			fmt.Fprintln(e.out, version.String())
			return nil
		},
	})
}
