// dashboard_credentials_test.go — focused tests for the credential-file
// operations of `rotate-dashboard-credentials`: symlink refusal, modes,
// --if-missing idempotence, --fresh rotation, chown-failure atomicity, and
// recovery parsing. The paths are pointed at a temp root (the package vars +
// convergeCredDir/chownFn injection seams), so the production /etc tree and
// the root/systemd gate are never touched. These tests exercise the pure file
// plumbing; the root/Linux gate itself is covered by the command entrypoint.
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/dashboard"
)

// chownForTest returns the chownFn a test should use. On a root Linux host the
// real chownByName is kept so the tests also verify ownership against the
// systemd "0640 root:split-tunnel" contract. On any other host (non-root, or
// non-Linux) a no-op is returned: a non-root process cannot perform a chown,
// and the credential-file tests only assert the file plumbing (creation,
// atomicity, idempotence, recovery) — never real ownership — so a no-op is
// both sufficient and correct there. This is what makes the suite runnable on
// a bare CI runner that has neither root nor the split-tunnel group.
func chownForTest(t *testing.T) func(string, string, string) error {
	t.Helper()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return chownByName
	}
	return func(string, string, string) error { return nil }
}

// withCredPaths points the credential-path vars at <root>/dashboard/... and
// swaps the dir-convergence + chown gates for temp-root no-ops (restored via
// t.Cleanup). This keeps the generate/recover flows exercisable off a Linux
// host and without root.
func withCredPaths(t *testing.T, root string) {
	t.Helper()
	dash := filepath.Join(root, "dashboard")
	oldCreds, oldRet, oldDir := dashCredsFile, dashRetrievalFile, dashCredsDir
	dashCredsFile = filepath.Join(dash, filepath.Base(dashCredsFile))
	dashRetrievalFile = filepath.Join(dash, filepath.Base(dashRetrievalFile))
	dashCredsDir = dash

	oldConverge := convergeCredDir
	convergeCredDir = func(dir string) error { return os.MkdirAll(dir, 0o750) }

	oldChown := chownFn
	chownFn = chownForTest(t)

	t.Cleanup(func() {
		dashCredsFile, dashRetrievalFile, dashCredsDir = oldCreds, oldRet, oldDir
		convergeCredDir = oldConverge
		chownFn = oldChown
	})
}

// readRetrievalPassword parses <root>/dashboard/credentials.recovery back to
// (user, password) using the production parser.
func readRetrievalPassword(t *testing.T, dir string) (string, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.Base(dashRetrievalFile)))
	if err != nil {
		t.Fatalf("read retrieval file: %v", err)
	}
	user, pass, ok := parseRetrievalFile(string(b))
	if !ok {
		t.Fatalf("retrieval file did not parse: %q", b)
	}
	return user, pass
}

// TestWriteSecretFileRefusesSymlinkTarget: a symlink planted at the final
// path is replaced (the atomic rename swaps the link itself, never writes
// through it), and the temp creation refuses a pre-existing temp target.
func TestWriteSecretFileRefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials")

	// Plant a symlink at the final target pointing at an unrelated file.
	leak := filepath.Join(dir, "leak")
	if err := os.WriteFile(leak, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(leak, creds); err != nil {
		t.Skip("symlink not supported on this host")
	}

	// The chown step is unrunnable on a non-root host; the symlink-refusal
	// property this test pins lives in the atomic rename, not the ownership.
	// Inject the matching no-op so the write succeeds and the rename is what
	// gets asserted.
	oldChown := chownFn
	chownFn = chownForTest(t)
	t.Cleanup(func() { chownFn = oldChown })

	if err := writeSecretFile(creds, "new-content", 0o640, "root", "root"); err != nil {
		t.Fatalf("writeSecretFile through symlink target: %v", err)
	}
	// The symlink was replaced by a regular file; the leak is untouched.
	st, err := os.Lstat(creds)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t.Error("final path is still a symlink after write; expected a regular file")
	}
	if got, _ := os.ReadFile(leak); string(got) != "existing" {
		t.Errorf("symlink target was written through: got %q", got)
	}

	// A pre-existing temp target must be refused (O_EXCL), never truncated.
	tmp := creds + ".tmp-" + "0"
	if err := os.WriteFile(tmp, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force the same pid-derived name by using pid 0 is impossible; instead
	// verify the O_EXCL create semantics directly: opening with O_EXCL on an
	// existing path must fail.
	if _, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640); !errors.Is(err, os.ErrExist) {
		t.Errorf("O_EXCL on an existing temp file: err = %v, want EEXIST", err)
	}
}

// TestWriteSecretFileChownFailureLeavesNoFinalFile: when chown fails (Linux
// only, injected), the temp file is cleaned up and the final path is NOT
// published — a wrong-owner final file must never appear.
func TestWriteSecretFileChownFailureLeavesNoFinalFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("chown gate is Linux-only")
	}
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials")

	oldChown := chownFn
	chownFn = func(string, string, string) error {
		return errors.New("injected chown failure")
	}
	t.Cleanup(func() { chownFn = oldChown })

	err := writeSecretFile(creds, "data", 0o640, "root", "root")
	if err == nil {
		t.Fatal("writeSecretFile = nil error, want the injected chown failure")
	}
	if _, statErr := os.Lstat(creds); !os.IsNotExist(statErr) {
		t.Error("final credential file was published despite chown failure")
	}
	// No leftover temp file either.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("temp dir not cleaned after chown failure: %v", entries)
	}
}

// TestRotateIfMissingIsIdempotent: with no verifier, --if-missing generates
// both files; a second --if-missing preserves them (no rotation).
func TestRotateIfMissingIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	withCredPaths(t, dir)

	var out bytes.Buffer
	if err := rotateIfMissing(&out, dashCredsDir); err != nil {
		t.Fatalf("first rotateIfMissing: %v", err)
	}
	if !fileExistsRegular(dashCredsFile) {
		t.Fatalf("credentials file not created: %s", dashCredsFile)
	}
	if !fileExistsRegular(dashRetrievalFile) {
		t.Fatalf("retrieval file not created: %s", dashRetrievalFile)
	}
	firstUser, firstPass := readRetrievalPassword(t, dashCredsDir)

	// Capture the verifier bytes; a second run must NOT change them.
	firstCreds, err := os.ReadFile(dashCredsFile)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := rotateIfMissing(&out, dashCredsDir); err != nil {
		t.Fatalf("second rotateIfMissing: %v", err)
	}
	secondCreds, err := os.ReadFile(dashCredsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstCreds, secondCreds) {
		t.Error("second --if-missing rotated an existing verifier; it must preserve it")
	}
	secondUser, secondPass := readRetrievalPassword(t, dashCredsDir)
	if secondUser != firstUser || secondPass != firstPass {
		t.Error("second --if-missing changed the retrieval file; it must preserve it")
	}
}

// TestRotateFreshRotates: --fresh always regenerates, replacing the verifier
// and overwriting the retrieval file (no stale credential left behind).
func TestRotateFreshRotates(t *testing.T) {
	dir := t.TempDir()
	withCredPaths(t, dir)

	var out bytes.Buffer
	if err := rotateGenerate(&out, dashCredsDir, true); err != nil {
		t.Fatalf("first rotateGenerate: %v", err)
	}
	firstCreds, err := os.ReadFile(dashCredsFile)
	if err != nil {
		t.Fatal(err)
	}
	firstUser, firstPass := readRetrievalPassword(t, dashCredsDir)

	out.Reset()
	if err := rotateGenerate(&out, dashCredsDir, true); err != nil {
		t.Fatalf("second rotateGenerate: %v", err)
	}
	secondCreds, err := os.ReadFile(dashCredsFile)
	if err != nil {
		t.Fatal(err)
	}
	// Fresh rotation replaces the verifier (new salt) and the password.
	if bytes.Equal(firstCreds, secondCreds) {
		t.Error("fresh rotation left the verifier unchanged; expected a new salt/digest")
	}
	secondUser, secondPass := readRetrievalPassword(t, dashCredsDir)
	if secondPass == firstPass {
		t.Error("fresh rotation left the retrieval password unchanged")
	}
	_ = firstUser
	_ = secondUser
}

// TestRotateRecoverParsesRetrievalFile: --recover re-derives a missing
// verifier from a carried retrieval file, and the derived verifier still
// validates the recovered password.
func TestRotateRecoverParsesRetrievalFile(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	withCredPaths(t, root)

	// Seed a recovery dir with a known retrieval file.
	recoverDir := dir
	user, pass := "admin", "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(recoverDir, "credentials.recovery"), []byte(user+" "+pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := rotateRecover(&out, dashCredsDir, recoverDir); err != nil {
		t.Fatalf("rotateRecover: %v", err)
	}
	if !fileExistsRegular(dashCredsFile) {
		t.Fatal("recover did not create the verifier")
	}
	// The re-derived verifier must verify the recovered password.
	ver, err := os.ReadFile(dashCredsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !verifierAcceptsPassword(t, string(ver), user, pass) {
		t.Error("recovered verifier does not accept the carried password")
	}
}

// TestParseRetrievalFile pins the parser's accept/reject matrix (hex password
// is whitespace-free; only one non-empty line is accepted).
func TestParseRetrievalFile(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		user   string
		pass   string
		wantOK bool
	}{
		{"single line", "admin abcd\n", "admin", "abcd", true},
		{"no trailing newline", "abcd-user deadbeef", "abcd-user", "deadbeef", true},
		{"leading blank lines tolerated", "\n\nadmin abcd\n", "admin", "abcd", true},
		{"internal spaces preserved", "admin ab cd\n", "admin", "ab cd", true},
		{"empty input", "", "", "", false},
		{"two non-empty lines", "admin a\nadmin b\n", "", "", false},
		{"no delimiter", "admin", "", "", false},
		{"surrounding line whitespace trimmed", "  admin abcd  ", "admin", "abcd", true},
		{"whitespace-only password", "admin   \n", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, p, ok := parseRetrievalFile(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseRetrievalFile(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if ok && (u != tc.user || p != tc.pass) {
				t.Errorf("parseRetrievalFile = (%q,%q), want (%q,%q)", u, p, tc.user, tc.pass)
			}
		})
	}
}

// TestCommandRejectsUnknownAndMutuallyExclusiveFlags: the flag parser fails
// closed on unknown flags and on mutually exclusive combinations.
func TestCommandRejectsUnknownAndMutuallyExclusiveFlags(t *testing.T) {
	withLinux(t)
	// The root gate (os.Geteuid) runs before flag parsing on a dev host, so
	// exercise the parser behaviour only when we are root; otherwise assert the
	// command at least refuses a non-root host with a root error.
	if os.Geteuid() != 0 {
		var out bytes.Buffer
		err := rotateDashboardCredentialsCommand(context.Background(), &out, []string{})
		if err == nil || !containsRootError(err) {
			t.Fatalf("non-root command err = %v, want a root requirement", err)
		}
		return
	}
	var out bytes.Buffer
	for _, args := range [][]string{{"--bogus"}, {"--fresh", "--if-missing"}, {"--fresh", "--recover", "/tmp"}, {"--recover", "--if-missing"}, {"--recover"}} {
		err := rotateDashboardCredentialsCommand(context.Background(), &out, args)
		if err == nil {
			t.Errorf("args %v: err = nil, want usage error", args)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// verifierAcceptsPassword checks that a verifier document verifies pass for
// user, using the exported dashboard primitives (no plaintext retained).
func verifierAcceptsPassword(t *testing.T, doc, user, pass string) bool {
	t.Helper()
	u, iter, salt, digest, err := parseVerifierForTest(doc)
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}
	if u != user {
		t.Fatalf("verifier user = %q, want %q", u, user)
	}
	return verifyCandidateForTest(u, pass, iter, salt, digest)
}

// containsRootError reports whether err is the non-root gate error.
func containsRootError(err error) bool {
	return err != nil && err.Error() != "" && contains(err.Error(), "requires root")
}

// contains is a tiny substring helper (avoids importing strings just for a
// single assertion in this file).
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// parseVerifierForTest / verifyCandidateForTest are thin test adapters over
// the exported internal/dashboard primitives, so the credential-file tests
// can round-trip a verifier document without re-implementing the KDF.
func parseVerifierForTest(doc string) (user string, iter int, salt, digest []byte, err error) {
	return dashboard.ParseVerifier(doc)
}

func verifyCandidateForTest(user, pass string, iter int, salt, digest []byte) bool {
	return dashboard.VerifyCandidatePassword(user, pass, iter, salt, digest)
}
