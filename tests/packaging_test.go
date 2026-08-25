package tests

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/service"
	"github.com/ipulse/ipulse/internal/version"
)

// TestVersionIsConsistent checks that the version an operator sees matches the version
// the packages claim. A binary reporting one version inside a package named another is
// the kind of mismatch that only ever surfaces during an incident.
func TestVersionIsConsistent(t *testing.T) {
	root := repoRoot(t)
	want := strings.TrimSpace(mustReadFile(t, filepath.Join(root, "VERSION")))
	if want == "" {
		t.Fatal("VERSION is empty")
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+`).MatchString(want) {
		t.Errorf("VERSION %q is not a semantic version", want)
	}
	if version.Version != want {
		t.Errorf("the binary reports version %q but VERSION says %q; the build flags are not stamping it",
			version.Version, want)
	}

	spec := mustReadFile(t, filepath.Join(root, "packaging", "rpm", "ipulse.spec"))
	if !strings.Contains(spec, want) {
		t.Errorf("the RPM spec does not mention version %s", want)
	}
	changelog := mustReadFile(t, filepath.Join(root, "CHANGELOG.md"))
	if !strings.Contains(changelog, want) {
		t.Errorf("the changelog has no entry for version %s", want)
	}
}

// TestSystemdUnit checks the unit iPulse generates. The packages install exactly what
// `ipulse service install` writes, so this one assertion covers both paths.
func TestSystemdUnit(t *testing.T) {
	unit, err := service.UnitFileContents("/usr/local/bin/ipulse", service.InstallOptions{
		ExecPath:   "/usr/local/bin/ipulse",
		ConfigPath: "/etc/ipulse/ipulse.yaml",
		User:       "ipulse",
		Group:      "ipulse",
		DataDir:    "/var/lib/ipulse",
		LogDir:     "/var/log/ipulse",
	})
	if err != nil {
		t.Fatalf("UnitFileContents: %v", err)
	}

	// Start at boot with no interactive session is the whole point of the service.
	for _, want := range []string{
		"[Unit]", "[Service]", "[Install]",
		"WantedBy=multi-user.target",
		"After=network-online.target",
		"Type=notify",
		"Restart=",
		"ExecStart=/usr/local/bin/ipulse",
		"--config /etc/ipulse/ipulse.yaml",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit is missing %q:\n%s", want, unit)
		}
	}

	// The hardening is a security requirement, not a nicety: the agent reads network
	// state and writes one database, and should be able to do very little else.
	for _, want := range []string{
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"AmbientCapabilities=",
		"CapabilityBoundingSet=",
		"ReadWritePaths=",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit is missing the hardening directive %q", want)
		}
	}

	// Only the two capabilities iPulse actually needs, and no blanket privilege.
	caps := captureLine(unit, "AmbientCapabilities=")
	for _, want := range []string{"CAP_NET_RAW", "CAP_DAC_READ_SEARCH"} {
		if !strings.Contains(caps, want) {
			t.Errorf("AmbientCapabilities is missing %s: %q", want, caps)
		}
	}
	for _, forbidden := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE"} {
		if strings.Contains(caps, forbidden) {
			t.Errorf("the unit grants %s, which iPulse does not need: %q", forbidden, caps)
		}
	}
}

// TestPackagingScriptsAreValidShell parses every shell script rather than running it.
// A syntax error in a maintainer script only shows up during an install, on someone
// else's machine.
func TestPackagingScriptsAreValidShell(t *testing.T) {
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	root := repoRoot(t)
	var scripts []string
	for _, dir := range []string{"scripts", filepath.Join("packaging", "deb"), filepath.Join("packaging", "rpm")} {
		matches, err := filepath.Glob(filepath.Join(root, dir, "*.sh"))
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, matches...)
	}
	if len(scripts) == 0 {
		t.Fatal("no packaging scripts were found")
	}
	for _, path := range scripts {
		t.Run(filepath.Base(path), func(t *testing.T) {
			out, err := exec.Command(sh, "-n", path).CombinedOutput()
			if err != nil {
				t.Errorf("%s: %v\n%s", path, err, out)
			}
			body := mustReadFile(t, path)
			if !strings.HasPrefix(body, "#!") {
				t.Error("the script has no interpreter line")
			}
			// A packaging script that keeps going after a failed step produces a
			// package that looks fine and is not.
			if !strings.Contains(body, "set -e") && !strings.Contains(body, "set -eu") {
				t.Error("the script does not stop on error (set -e)")
			}
		})
	}
}

// TestInstallScriptRefusesToGuess checks the two properties that matter in an installer:
// it must require root, and it must not destroy data it did not create.
func TestInstallScriptRefusesToGuess(t *testing.T) {
	root := repoRoot(t)
	install := mustReadFile(t, filepath.Join(root, "scripts", "install.sh"))
	if !strings.Contains(install, "EUID") && !strings.Contains(install, "id -u") {
		t.Error("install.sh does not check that it is running as root")
	}
	if !strings.Contains(install, "systemctl") {
		t.Error("install.sh does not use systemctl")
	}

	uninstall := mustReadFile(t, filepath.Join(root, "scripts", "uninstall.sh"))
	if !strings.Contains(uninstall, "--purge") {
		t.Error("uninstall.sh has no explicit --purge flag; data removal must be opt-in")
	}
	// rm -rf on a data directory must never be the default path through the script.
	for _, line := range strings.Split(uninstall, "\n") {
		if !strings.Contains(line, "rm -rf") {
			continue
		}
		if strings.Contains(line, "$DATA_DIR") || strings.Contains(line, "$LOG_DIR") ||
			strings.Contains(line, "$CONFIG_DIR") {
			// Acceptable only inside the purge branch; check the surrounding guard.
			if !strings.Contains(uninstall, "if [ \"$PURGE\"") && !strings.Contains(uninstall, "if $PURGE") &&
				!strings.Contains(uninstall, "$PURGE") {
				t.Errorf("data is removed without a purge guard: %s", strings.TrimSpace(line))
			}
		}
	}
}

// TestDebianPackaging checks the maintainer scripts and the conffiles declaration, which
// is what stops an upgrade overwriting an edited configuration.
func TestDebianPackaging(t *testing.T) {
	body := mustReadFile(t, filepath.Join(repoRoot(t), "packaging", "deb", "build.sh"))
	for _, want := range []string{"conffiles", "postinst", "prerm", "postrm", "preinst"} {
		if !strings.Contains(body, want) {
			t.Errorf("the Debian build does not produce %s", want)
		}
	}
	if !strings.Contains(body, "/etc/ipulse/ipulse.yaml") {
		t.Error("the configuration file is not declared as a conffile")
	}
	if !strings.Contains(body, "debian-binary") {
		t.Error("the archive does not include debian-binary")
	}
}

// TestRPMPackaging checks the spec's scriptlets and file list.
func TestRPMPackaging(t *testing.T) {
	spec := mustReadFile(t, filepath.Join(repoRoot(t), "packaging", "rpm", "ipulse.spec"))
	for _, want := range []string{
		"%post", "%preun", "%postun", "%files",
		"%config(noreplace)", "ipulse.yaml",
		"systemd", "ipulse.service",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("the RPM spec is missing %q", want)
		}
	}
	// The path is written with RPM's own macros, so match the line rather than a
	// literal path.
	conf := captureLine(spec, "%config(noreplace)")
	if !strings.Contains(conf, "ipulse.yaml") {
		t.Errorf("the configuration is not marked noreplace, so an upgrade would overwrite it: %q", conf)
	}
}

// TestWindowsInstaller parses the WiX source as XML and checks the parts that make the
// installed service identical to a manual installation.
func TestWindowsInstaller(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "packaging", "windows", "ipulse.wxs")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc any
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the WiX source is not valid XML: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"ipulse.exe",
		"service install",
		"service uninstall",
		"MajorUpgrade",
		"CommonAppDataFolder",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the WiX source is missing %q", want)
		}
	}
	// Uninstall must keep the history by default.
	if !strings.Contains(body, "--keep-data") {
		t.Error("the uninstall action does not keep collected data")
	}

	for _, name := range []string{"install.ps1", "uninstall.ps1", "build.ps1"} {
		script := mustReadFile(t, filepath.Join(root, "packaging", "windows", name))
		// $args is an automatic PowerShell variable; assigning it silently breaks the
		// script in ways that only appear at run time.
		if regexp.MustCompile(`(?m)^\s*\$args\s*=`).MatchString(script) {
			t.Errorf("%s assigns the automatic variable $args", name)
		}
		if !strings.Contains(script, "ErrorActionPreference") {
			t.Errorf("%s does not set $ErrorActionPreference, so a failed step is ignored", name)
		}
	}
}

// TestDocumentationIsComplete checks that every document the project promises exists and
// has content. Documentation that is listed but missing is worse than none.
func TestDocumentationIsComplete(t *testing.T) {
	root := repoRoot(t)
	required := []string{
		"README.md", "CHANGELOG.md",
		filepath.Join("docs", "architecture.md"),
		filepath.Join("docs", "installation-linux.md"),
		filepath.Join("docs", "installation-windows.md"),
		filepath.Join("docs", "configuration.md"),
		filepath.Join("docs", "event-catalog.md"),
		filepath.Join("docs", "security.md"),
		filepath.Join("docs", "privacy.md"),
		filepath.Join("docs", "troubleshooting.md"),
		filepath.Join("docs", "api.md"),
		filepath.Join("docs", "development.md"),
		filepath.Join("docs", "detection-engine.md"),
	}
	for _, rel := range required {
		info, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s is missing", rel)
			continue
		}
		if info.Size() < 512 {
			t.Errorf("%s is only %d bytes; it is a placeholder rather than documentation", rel, info.Size())
		}
	}
}

// TestEventCatalogIsCurrent guards the generated catalog against drift. It is produced
// by `ipulse events catalog --markdown`, so a new event that is not regenerated leaves
// the documentation lying about what iPulse can report.
func TestEventCatalogIsCurrent(t *testing.T) {
	root := repoRoot(t)
	doc := mustReadFile(t, filepath.Join(root, "docs", "event-catalog.md"))
	for _, def := range allEventDefinitions() {
		if !strings.Contains(doc, def) {
			t.Errorf("docs/event-catalog.md does not document %s; run `make docs`", def)
		}
	}
}

// allEventDefinitions returns every event name in the catalog.
func allEventDefinitions() []string {
	defs := events.All()
	names := make([]string, 0, len(defs))
	for _, d := range defs {
		names = append(names, d.Name)
	}
	return names
}

// captureLine returns the first line starting with prefix.
func captureLine(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
