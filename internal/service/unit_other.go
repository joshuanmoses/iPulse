//go:build !linux

package service

// UnitFileContents renders a systemd unit. It is available on every platform so a
// package for Linux can be built from any host, which is what the cross-compiling
// build scripts do.
func UnitFileContents(exe string, opts InstallOptions) (string, error) {
	return renderUnitPortable(exe, opts)
}
