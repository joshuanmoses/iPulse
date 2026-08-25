//go:build windows

package main

import "os"

// registerReloadSignal is a no-op on Windows: there is no SIGHUP. Configuration reload
// is requested through the service control channel, or by restarting the service.
func registerReloadSignal(chan os.Signal) {}
