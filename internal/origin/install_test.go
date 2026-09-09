package origin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// staticDL serves fixed bytes per URL; keeps the install logic
// network-independent. blockOnCtx makes Fetch wait for the caller's ctx
// (cancellation-injection tests).
type staticDL struct {
	files      map[string][]byte
	err        error
	blockOnCtx bool
}

func (s staticDL) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.blockOnCtx {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b, ok := s.files[url]
	if !ok {
		return nil, fmt.Errorf("staticDL: no file for %s", url)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// fakeExec records calls and returns canned results. blockOnCtx makes
// VersionOutput/Validate wait for the caller's ctx.
type fakeExec struct {
	versionOut  string
	versionErr  error
	validateOut string
	validateErr error
	calls       []string
	blockOnCtx  bool
}

func (f *fakeExec) VersionOutput(ctx context.Context, bin string) (string, error) {
	f.calls = append(f.calls, "version:"+bin)
	if f.blockOnCtx {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return f.versionOut, f.versionErr
}
func (f *fakeExec) Validate(ctx context.Context, bin, config string) (string, error) {
	f.calls = append(f.calls, "validate:"+bin+":"+config)
	if f.blockOnCtx {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return f.validateOut, f.validateErr
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// makeTarGz builds a release-shaped tar.gz (FLAT layout, like the
// official caddy release): caddy binary, LICENSE, README.md.
func makeTarGz(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	add := func(name, content string, mode int64) {
		t.Helper()
		hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	add("caddy", "FAKE-CADDY-BINARY-v2.11.4", 0o755)
	add("LICENSE", "license", 0o644)
	add("README.md", "readme", 0o644)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return gz.Bytes()
}

func checksumsFor(t *testing.T, tarBytes []byte) []byte {
	t.Helper()
	name, _ := TarName(PinnedVersion, CaddyArchLinuxAMD64)
	return checksumsFile(fmt.Sprintf("%s  %s", sha512For(t, tarBytes), name))
}

// installFixture wires a staticDL + fakeExec + prefix for an install of
// the pinned version, linux-amd64.
func installFixture(t *testing.T, tarBytes []byte) (*Installer, *fakeExec, string) {
	t.Helper()
	prefix := t.TempDir()
	ta, err := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ChecksumURL(PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	dl := staticDL{files: map[string][]byte{ta: tarBytes, ca: checksumsFor(t, tarBytes)}}
	fe := &fakeExec{versionOut: PinnedVersion + " h1:fakebuildhash"}
	in := &Installer{Prefix: prefix, DL: dl, Exec: fe}
	return in, fe, prefix
}

// ---------------------------------------------------------------------------
// Install (happy path + failure containment)
// ---------------------------------------------------------------------------

func TestInstallHappyPath(t *testing.T) {
	tarBytes := makeTarGz(t)
	in, fe, prefix := installFixture(t, tarBytes)

	got, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	wantDir, _ := VersionDir(prefix, PinnedVersion)
	if got.Path != filepath.Join(wantDir, "caddy") {
		t.Errorf("Path = %q", got.Path)
	}
	if got.Version != PinnedVersion || got.Arch != "amd64" {
		t.Errorf("manifest = %+v", got)
	}
	if got.TarSHA512 != sha512For(t, tarBytes) {
		t.Errorf("TarSHA512 = %q, want the verified checksum of the tar", got.TarSHA512)
	}
	b, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatalf("binary not at %s: %v", got.Path, err)
	}
	if string(b) != "FAKE-CADDY-BINARY-v2.11.4" {
		t.Errorf("binary content = %q", b)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(got.Path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o100 == 0 {
			t.Error("binary not executable")
		}
	}
	foundSmoke := false
	for _, c := range fe.calls {
		if strings.HasPrefix(c, "version:") && strings.HasSuffix(c, "caddy") {
			foundSmoke = true
		}
	}
	if !foundSmoke {
		t.Errorf("smoke check not called; calls=%v", fe.calls)
	}
	assertNoStageDirs(t, prefix)
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("Installed not JSON-serializable: %v", err)
	}
}

// A failed install must NOT leave a partial version dir, a stale stage
// dir, and must NOT touch a previously installed version.
func TestInstallFailureLeavesNoPartialState(t *testing.T) {
	tarBytes := makeTarGz(t)
	in, fe, prefix := installFixture(t, tarBytes)

	// First: install an OLD version successfully (the rollback source).
	oldTar := makeTarGz(t)
	oldTA, _ := TarURL("v9.9.9", CaddyArchLinuxAMD64)
	oldCA, _ := ChecksumURL("v9.9.9")
	oldName, _ := TarName("v9.9.9", CaddyArchLinuxAMD64)
	oldDL := staticDL{files: map[string][]byte{
		oldTA: oldTar,
		oldCA: checksumsFile(fmt.Sprintf("%s  %s", sha512For(t, oldTar), oldName)),
	}}
	oldIn := &Installer{Prefix: prefix, DL: oldDL, Exec: &fakeExec{versionOut: "v9.9.9 h1:old"}}
	if _, err := oldIn.Install(context.Background(), "v9.9.9", CaddyArchLinuxAMD64, ""); err != nil {
		t.Fatalf("old install: %v", err)
	}
	oldDir, _ := VersionDir(prefix, "v9.9.9")
	if _, err := os.Stat(filepath.Join(oldDir, "caddy")); err != nil {
		t.Fatalf("old version not installed: %v", err)
	}

	// Now a NEW install that fails the config gate.
	fe.validateErr = errors.New("config rejected")
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "/etc/split-tunnel/Caddyfile")
	if err == nil {
		t.Fatal("expected config-gate failure")
	}
	if !strings.Contains(err.Error(), "caddy validate") {
		t.Errorf("error should name the gate: %v", err)
	}
	newDir, _ := VersionDir(prefix, PinnedVersion)
	if _, statErr := os.Stat(newDir); !os.IsNotExist(statErr) {
		t.Errorf("partial version dir left behind: %s (stat err %v)", newDir, statErr)
	}
	assertNoStageDirs(t, prefix)
	if b, rErr := os.ReadFile(filepath.Join(oldDir, "caddy")); rErr != nil || string(b) != "FAKE-CADDY-BINARY-v2.11.4" {
		t.Errorf("previously installed version disturbed: %v %q", rErr, b)
	}
}

func TestInstallChecksumMismatchAborts(t *testing.T) {
	tarBytes := makeTarGz(t)
	prefix := t.TempDir()
	ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	ca, _ := ChecksumURL(PinnedVersion)
	name, _ := TarName(PinnedVersion, CaddyArchLinuxAMD64)
	dl := staticDL{files: map[string][]byte{
		ta: tarBytes,
		ca: checksumsFile(fmt.Sprintf("%s  %s", strings.Repeat("ab", sha512.Size), name)), // wrong checksum
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: PinnedVersion + " h1:x"}}
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if !strings.Contains(err.Error(), "SHA-512 mismatch") {
		t.Errorf("wrong error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, "caddy", PinnedVersion)); !os.IsNotExist(statErr) {
		t.Error("version dir created despite checksum failure")
	}
}

func TestInstallMissingChecksumRejected(t *testing.T) {
	tarBytes := makeTarGz(t)
	prefix := t.TempDir()
	ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	ca, _ := ChecksumURL(PinnedVersion)
	dl := staticDL{files: map[string][]byte{
		ta: tarBytes,
		ca: []byte("# no entries\n"), // no line for the tar
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: PinnedVersion + " h1:x"}}
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err == nil {
		t.Fatal("expected rejection of release without a checksum entry")
	}
	if !strings.Contains(err.Error(), "no SHA-512 entry") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestInstallSmokeCheckFailureCleansUp(t *testing.T) {
	tarBytes := makeTarGz(t)
	in, fe, prefix := installFixture(t, tarBytes)
	fe.versionOut = "not the pinned version" // smoke: first field != version
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err == nil {
		t.Fatal("expected smoke failure")
	}
	if !strings.Contains(err.Error(), "smoke") {
		t.Errorf("wrong error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, "caddy", PinnedVersion)); !os.IsNotExist(statErr) {
		t.Error("version dir left after smoke failure")
	}
	assertNoStageDirs(t, prefix)
}

func TestInstallExistingVersionRefusedWithoutForce(t *testing.T) {
	tarBytes := makeTarGz(t)
	in, _, _ := installFixture(t, tarBytes)
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("second install should be refused")
	}
	in.Force = true
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err != nil {
		t.Fatalf("forced reinstall: %v", err)
	}
}

func TestRemoveVersionPrefixGuard(t *testing.T) {
	prefix := t.TempDir()
	in := &Installer{Prefix: prefix}
	if err := in.RemoveVersion(".."); err == nil {
		t.Error("RemoveVersion(\"..\") should be refused")
	}
	if err := in.RemoveVersion("v9.9.9"); err != nil {
		t.Fatalf("RemoveVersion on non-existent dir: %v", err)
	}
}

// assertNoStageDirs fails if a crashed-install stage dir is left behind.
func assertNoStageDirs(t *testing.T, prefix string) {
	t.Helper()
	entries, err := os.ReadDir(prefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".caddy-stage-") {
			t.Errorf("stale stage dir left behind: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// Tar safety
// ---------------------------------------------------------------------------

func makeTarWithEntry(t *testing.T, name, content string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	add := func(name, content string) {
		t.Helper()
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	add(name, content)
	add("caddy", "FAKE")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return gz.Bytes()
}

func TestTarSlipRejected(t *testing.T) {
	for _, evil := range []string{
		"../evil",
		"../../etc/passwd",
		"/absolute/evil",
		"a/../../evil",
	} {
		tarBytes := makeTarWithEntry(t, evil, "x")
		prefix := t.TempDir()
		ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
		ca, _ := ChecksumURL(PinnedVersion)
		name, _ := TarName(PinnedVersion, CaddyArchLinuxAMD64)
		dl := staticDL{files: map[string][]byte{ta: tarBytes, ca: checksumsFile(fmt.Sprintf("%s  %s", sha512For(t, tarBytes), name))}}
		in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: PinnedVersion + " h1:x"}}
		_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
		if err == nil {
			t.Errorf("tar-slip entry %q accepted", evil)
			continue
		}
		if !strings.Contains(err.Error(), "unsafe") && !strings.Contains(err.Error(), "extraction") {
			t.Errorf("tar-slip %q: wrong error: %v", evil, err)
		}
		assertNoStageDirs(t, prefix)
	}
}

// A symlink entry in the release tar is refused outright.
func TestTarSymlinkEntryRejected(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "caddy", Mode: 0o755, Size: 4}); err != nil {
		t.Fatal(err)
	}
	io.WriteString(tw, "FAKE")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw.Bytes())
	zw.Close()

	prefix := t.TempDir()
	ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	ca, _ := ChecksumURL(PinnedVersion)
	name, _ := TarName(PinnedVersion, CaddyArchLinuxAMD64)
	dl := staticDL{files: map[string][]byte{ta: gz.Bytes(), ca: checksumsFile(fmt.Sprintf("%s  %s", sha512For(t, gz.Bytes()), name))}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: PinnedVersion + " h1:x"}}
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err == nil {
		t.Fatal("symlink entry accepted")
	}
	assertNoStageDirs(t, prefix)
}

func TestInstallOversizedChecksumsRejected(t *testing.T) {
	tarBytes := makeTarGz(t)
	prefix := t.TempDir()
	ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	ca, _ := ChecksumURL(PinnedVersion)
	dl := staticDL{files: map[string][]byte{
		ta: tarBytes,
		ca: bytes.Repeat([]byte("x"), maxChecksumBytes+1),
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: PinnedVersion + " h1:x"}}
	_, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err == nil {
		t.Fatal("expected rejection of oversized checksums file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("wrong error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// HTTP downloader wiring (local test server; no external network)
// ---------------------------------------------------------------------------

func TestHTTPDownloaderAgainstLocalServer(t *testing.T) {
	tarBytes := makeTarGz(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/tar", func(w http.ResponseWriter, r *http.Request) { w.Write(tarBytes) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dl := HTTPDownloader{}
	rc, err := dl.Fetch(context.Background(), srv.URL+"/tar")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(body, tarBytes) {
		t.Error("downloaded body mismatch")
	}
	if _, err := dl.Fetch(context.Background(), srv.URL+"/404"); err == nil {
		t.Error("404 accepted")
	}
}
