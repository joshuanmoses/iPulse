package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/ipulse/ipulse/web"
)

// staticHandler serves the embedded dashboard.
//
// Paths that do not name a real asset fall back to the application shell, so the
// single-page application can own its own routing, while a missing asset (something with
// a file extension) still returns a genuine 404 rather than a page of HTML.
func (s *Server) staticHandler() http.Handler {
	sub, err := web.FS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusInternalServerError, "assets_unavailable", err.Error())
		})
	}
	fileServer := http.FileServer(http.FS(sub))

	serveShell := func(w http.ResponseWriter, r *http.Request) {
		// The shell is served for "/" directly: rewriting the path to "index.html"
		// would make the file server redirect back to "/", costing a round trip on
		// every page load.
		shell := r.Clone(r.Context())
		shell.URL.Path = "/"
		fileServer.ServeHTTP(w, shell)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Dashboard.Enabled {
			writeError(w, http.StatusNotFound, "dashboard_disabled",
				"the dashboard is disabled in configuration")
			return
		}

		// path.Clean resolves any traversal attempt before the path is used.
		clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if clean == "" || clean == "." || clean == "index.html" {
			serveShell(w, r)
			return
		}

		if _, err := fs.Stat(sub, clean); err != nil {
			if strings.Contains(path.Base(clean), ".") {
				writeError(w, http.StatusNotFound, "not_found", "no such asset")
				return
			}
			serveShell(w, r)
			return
		}

		// Assets are embedded and change only when the binary does, so a short cache
		// with revalidation is safe and keeps the dashboard responsive.
		w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		asset := r.Clone(r.Context())
		asset.URL.Path = "/" + clean
		fileServer.ServeHTTP(w, asset)
	})
}
