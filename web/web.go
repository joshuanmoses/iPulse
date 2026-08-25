// Package web embeds the iPulse dashboard assets.
//
// The dashboard is compiled into the binary so an installation is a single file: there
// is no asset directory to deploy, no CDN to reach, and the dashboard works unchanged on
// an air-gapped host.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:assets
var assets embed.FS

// FS returns the dashboard file system, rooted at the asset directory.
func FS() (fs.FS, error) { return fs.Sub(assets, "assets") }
