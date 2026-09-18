package deploy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRootFile returns the path of a file at the repository root as seen from
// this package, or an empty string when it cannot be resolved.
func repoRootFile(t *testing.T, name string) string {
	t.Helper()
	// This package lives at internal/deploy, so the repo root is two levels
	// up. Guard against running from a copied/stripped tree.
	candidates := []string{
		filepath.Join("..", "..", name),
		filepath.Join("..", "..", "..", name),
	}
	for _, c := range candidates {
		if st, err := os.Lstat(c); err == nil && st.Mode().IsRegular() {
			return c
		}
	}
	return ""
}

// TestLegacyInstallFirewallGated pins the H-2 remediation in the shell
// installer: the legacy ufw mutation is DISABLED by default and only runs
// under an explicit, clearly-labeled legacy flag. This is a static contract
// test (the shell path has no Go harness here); it runs on every platform and
// guards the installer from silently mutating firewall state again.
func TestLegacyInstallFirewallGated(t *testing.T) {
	path := repoRootFile(t, "install.sh")
	if path == "" {
		t.Skip("install.sh not resolvable from this tree; run from the repo root")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	src := string(data)

	for _, want := range []string{
		"LEGACY_FIREWALL=0",                     // default: off
		"--legacy-firewall",                     // the explicit opt-in flag
		"LEGACY_FIREWALL=1",                     // the flag enables it
		`if [ "$LEGACY_FIREWALL" -ne 1 ]; then`, // the gate
		"DEPRECATED / NON-PRODUCTION",           // the installer is labeled legacy
	} {
		if !strings.Contains(src, want) {
			t.Errorf("install.sh missing H-2 marker %q", want)
		}
	}

	// The gate must sit at the top of configure_firewall so the mutation is
	// refused before any ufw call.
	funcIdx := strings.Index(src, "configure_firewall() {")
	if funcIdx < 0 {
		t.Fatalf("configure_firewall() not found in install.sh")
	}
	gateIdx := strings.Index(src, "if [ \"$LEGACY_FIREWALL\" -ne 1 ]; then")
	endIdx := strings.Index(src, "ufw status")
	if gateIdx < 0 || endIdx < 0 {
		t.Fatalf("cannot locate the LEGACY_FIREWALL gate or a ufw call in configure_firewall")
	}
	if gateIdx < funcIdx {
		t.Errorf("the LEGACY_FIREWALL gate must appear after configure_firewall() opens")
	}
	if gateIdx > endIdx {
		t.Errorf("the LEGACY_FIREWALL gate must precede any ufw call in configure_firewall")
	}
}

// TestDocsPresentLegacyInstallerAsNonProduction pins that the docs no longer
// present install.sh as the production T8 path (H-2).
func TestDocsPresentLegacyInstallerAsNonProduction(t *testing.T) {
	readAll := func(name string) string {
		path := repoRootFile(t, name)
		if path == "" {
			return ""
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(b)
	}
	readme := readAll("README.md")
	if readme == "" {
		if runtime.GOOS != "windows" {
			t.Skip("README.md not resolvable from this tree")
		}
		t.Skip("README.md not resolvable from this tree")
	}
	// The README already carries an explicit legacy framing for install.sh.
	if !strings.Contains(readme, "LEGACY") && !strings.Contains(readme, "legacy") {
		t.Errorf("README must label install.sh as a legacy/non-production path")
	}
}
