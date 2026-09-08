package xray

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// staticDL serves fixed bytes per URL (zip/dgst); keeps the install
// logic network-independent.
type staticDL struct {
	files map[string][]byte
	err   error
}

func (s staticDL) Fetch(url string) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	b, ok := s.files[url]
	if !ok {
		return nil, fmt.Errorf("staticDL: no file for %s", url)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// fakeExec records calls and returns canned results.
type fakeExec struct {
	versionOut string
	versionErr error
	runTestOut string
	runTestErr error
	keyErr     error
	calls      []string
}

func (f *fakeExec) VersionOutput(bin string) (string, error) {
	f.calls = append(f.calls, "version:"+bin)
	return f.versionOut, f.versionErr
}
func (f *fakeExec) RunTest(bin, config string) (string, error) {
	f.calls = append(f.calls, "run-test:"+bin+":"+config)
	return f.runTestOut, f.runTestErr
}
func (f *fakeExec) Keypair(bin string) (string, error) {
	f.calls = append(f.calls, "keypair:"+bin)
	return "PrivateKey: pk\nPassword (PublicKey): uk\nHash32: h32\n", f.keyErr
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// makeZip builds a release-shaped zip (flat layout, like the official
// Xray-linux-64.zip): xray binary, LICENSE, README.md, geodata.
func makeZip(t *testing.T, withGeo bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		t.Helper()
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
	add("xray", "FAKE-XRAY-BINARY-v26.3.27")
	add("LICENSE", "license")
	add("README.md", "readme")
	if withGeo {
		add("geoip.dat", "GEOIP")
		add("geosite.dat", "GEOSITE")
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dgstFor(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// dgstFile renders the upstream .dgst format for the given sha256.
func dgstFile(sha string) []byte {
	return []byte("MD5= 00000000000000000000000000000000\nSHA1= 0000000000000000000000000000000000000000\nSHA2-256= " + sha + "\nSHA2-512= 00\n")
}

// installFixture wires a staticDL + fakeExec + prefix for an install of
// the pinned version, linux-64.
func installFixture(t *testing.T, zipBytes []byte) (*Installer, *fakeExec, string) {
	t.Helper()
	prefix := t.TempDir()
	zu, err := ZipURL(PinnedVersion, ArchLinux64)
	if err != nil {
		t.Fatal(err)
	}
	du, err := DigestURL(PinnedVersion, ArchLinux64)
	if err != nil {
		t.Fatal(err)
	}
	dl := staticDL{files: map[string][]byte{
		zu: zipBytes,
		du: dgstFile(dgstFor(t, zipBytes)),
	}}
	fe := &fakeExec{versionOut: "Xray 26.3.27 (fake)"}
	in := &Installer{Prefix: prefix, DL: dl, Exec: fe}
	return in, fe, prefix
}

// ---------------------------------------------------------------------------
// Version pin & asset resolution
// ---------------------------------------------------------------------------

func TestPinnedVersionShape(t *testing.T) {
	if !ValidVersion(PinnedVersion) {
		t.Errorf("PinnedVersion %q does not match vM.m.p", PinnedVersion)
	}
}

func TestAssetURLs(t *testing.T) {
	// The official release asset for linux/amd64 is Xray-linux-64.zip
	// (NOT Xray-linux-amd64.zip) — the installer must use the real name.
	zipURL, err := ZipURL(PinnedVersion, ArchLinux64)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/XTLS/Xray-core/releases/download/" + PinnedVersion + "/Xray-linux-64.zip"
	if zipURL != want {
		t.Errorf("ZipURL = %q, want %q", zipURL, want)
	}
	dgstURL, err := DigestURL(PinnedVersion, ArchLinux64)
	if err != nil {
		t.Fatal(err)
	}
	if dgstURL != zipURL+".dgst" {
		t.Errorf("DigestURL = %q, want %q", dgstURL, zipURL+".dgst")
	}
	if _, err := ZipURL("v26.3.27", Arch("linux-amd64")); err == nil {
		t.Error("unknown arch accepted")
	}
	if _, err := ZipURL("latest", ArchLinux64); err == nil {
		t.Error("invalid version accepted")
	}
	if _, err := ZipURL("v26.3.27-beta.1", ArchLinux64); err == nil {
		t.Error("prerelease tag accepted (pin must be stable-only)")
	}
}

func TestArchForGOARCH(t *testing.T) {
	cases := map[string]Arch{"amd64": ArchLinux64, "arm64": ArchLinuxARM64, "arm": ArchLinuxARM7, "386": ArchLinux32}
	for goarch, want := range cases {
		got, err := ArchForGOARCH(goarch)
		if err != nil || got != want {
			t.Errorf("ArchForGOARCH(%s) = %v, %v; want %v", goarch, got, err, want)
		}
	}
	if _, err := ArchForGOARCH("s390x"); err == nil {
		t.Error("unsupported arch accepted")
	}
}

// ---------------------------------------------------------------------------
// .dgst parsing
// ---------------------------------------------------------------------------

func TestParseDigest(t *testing.T) {
	good := "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
	if got, err := ParseDigest(dgstFile(good)); err != nil || got != good {
		t.Errorf("ParseDigest = %q, %v", got, err)
	}
	// Colon variant tolerated.
	colon := []byte("SHA2-256: " + good + "\n")
	if got, err := ParseDigest(colon); err != nil || got != good {
		t.Errorf("colon variant = %q, %v", got, err)
	}
	// Uppercase normalized to lowercase.
	upper := []byte("SHA2-256= " + strings.ToUpper(good) + "\n")
	if got, err := ParseDigest(upper); err != nil || got != good {
		t.Errorf("uppercase = %q, %v", got, err)
	}
	if _, err := ParseDigest(nil); !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: %v", err)
	}
	if _, err := ParseDigest([]byte("MD5= 0123\nSHA1= 0123\n")); err == nil {
		t.Error("missing SHA2-256 accepted")
	}
	if _, err := ParseDigest([]byte("SHA2-256= zzz\n")); err == nil {
		t.Error("malformed hex accepted")
	}
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("the zip bytes")
	good := dgstFor(t, data)
	if err := VerifyFile(data, good); err != nil {
		t.Errorf("match: %v", err)
	}
	if err := VerifyFile(data, strings.Repeat("0", 64)); err == nil {
		t.Error("mismatch accepted")
	}
	if err := VerifyFile(data, "abc"); err == nil {
		t.Error("short digest accepted")
	}
}

// ---------------------------------------------------------------------------
// Install (happy path + failure containment)
// ---------------------------------------------------------------------------

func TestInstallHappyPath(t *testing.T) {
	zipBytes := makeZip(t, true)
	in, fe, prefix := installFixture(t, zipBytes)
	in.WithGeodata = true

	got, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	wantDir, _ := VersionDir(prefix, PinnedVersion)
	if got.Path != filepath.Join(wantDir, "xray") {
		t.Errorf("Path = %q", got.Path)
	}
	if got.Version != PinnedVersion || got.Arch != "linux-64" {
		t.Errorf("manifest = %+v", got)
	}
	if got.ZipSHA256 != dgstFor(t, zipBytes) {
		t.Errorf("ZipSHA256 = %q, want the verified digest of the zip", got.ZipSHA256)
	}
	// Binary present, correct content.
	b, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatalf("binary not at %s: %v", got.Path, err)
	}
	if string(b) != "FAKE-XRAY-BINARY-v26.3.27" {
		t.Errorf("binary content = %q", b)
	}
	// Executable on unix hosts (Windows has no meaningful exec bit).
	if runtime.GOOS != "windows" {
		st, err := os.Stat(got.Path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o100 == 0 {
			t.Error("binary not executable")
		}
	}
	// Geodata extracted (WithGeodata=true).
	if _, err := os.Stat(filepath.Join(wantDir, "geoip.dat")); err != nil {
		t.Errorf("geoip.dat missing: %v", err)
	}
	// Smoke check ran against the installed binary.
	foundSmoke := false
	for _, c := range fe.calls {
		if strings.HasPrefix(c, "version:") && strings.HasSuffix(c, "xray") {
			foundSmoke = true
		}
	}
	if !foundSmoke {
		t.Errorf("smoke check not called; calls=%v", fe.calls)
	}
	// No stale stage dir left behind.
	assertNoStageDirs(t, prefix)
	// Manifest is JSON-serializable (it lands in /etc/split-tunnel/*.json).
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("Installed not JSON-serializable: %v", err)
	}
}

func TestInstallGeodataSkippedByDefault(t *testing.T) {
	zipBytes := makeZip(t, true)
	in, _, prefix := installFixture(t, zipBytes) // default: WithGeodata=false
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	dir, _ := VersionDir(prefix, PinnedVersion)
	if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); !os.IsNotExist(err) {
		t.Error("geoip.dat extracted despite WithGeodata=false")
	}
	if _, err := os.Stat(filepath.Join(dir, "xray")); err != nil {
		t.Error("binary missing")
	}
}

func TestInstallWithGeodata(t *testing.T) {
	zipBytes := makeZip(t, true)
	in, _, prefix := installFixture(t, zipBytes)
	in.WithGeodata = true
	if _, err := in.Install(PinnedVersion, ArchLinux64, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}
	dir, _ := VersionDir(prefix, PinnedVersion)
	if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); err != nil {
		t.Errorf("geoip.dat missing with WithGeodata=true: %v", err)
	}
}

// A failed install must NOT leave a partial version dir, a stale stage
// dir, and must NOT touch a previously installed version (rollback =
// old dir still there).
func TestInstallFailureLeavesNoPartialState(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, fe, prefix := installFixture(t, zipBytes)

	// First: install an OLD version successfully (the rollback source).
	oldZip := makeZip(t, false)
	oldDL := staticDL{files: map[string][]byte{
		mustURL(t, "v9.9.9", ArchLinux64, false): oldZip,
		mustURL(t, "v9.9.9", ArchLinux64, true):  dgstFile(dgstFor(t, oldZip)),
	}}
	oldIn := &Installer{Prefix: prefix, DL: oldDL, Exec: &fakeExec{versionOut: "Xray 9.9.9"}}
	if _, err := oldIn.Install("v9.9.9", ArchLinux64, ""); err != nil {
		t.Fatalf("old install: %v", err)
	}
	oldDir, _ := VersionDir(prefix, "v9.9.9")
	if _, err := os.Stat(filepath.Join(oldDir, "xray")); err != nil {
		t.Fatalf("old version not installed: %v", err)
	}

	// Now a NEW install that fails the config gate.
	fe.runTestErr = fmt.Errorf("config rejected")
	_, err := in.Install(PinnedVersion, ArchLinux64, "/etc/split-tunnel/xray.json")
	if err == nil {
		t.Fatal("expected config-gate failure")
	}
	if !strings.Contains(err.Error(), "run -test") {
		t.Errorf("error should name the gate: %v", err)
	}
	// No partial new version dir, no stale stage dir.
	newDir, _ := VersionDir(prefix, PinnedVersion)
	if _, statErr := os.Stat(newDir); !os.IsNotExist(statErr) {
		t.Errorf("partial version dir left behind: %s (stat err %v)", newDir, statErr)
	}
	assertNoStageDirs(t, prefix)
	// The old (active) version is untouched.
	if b, rErr := os.ReadFile(filepath.Join(oldDir, "xray")); rErr != nil || string(b) != "FAKE-XRAY-BINARY-v26.3.27" {
		t.Errorf("previously installed version disturbed: %v %q", rErr, b)
	}
}

func TestInstallChecksumMismatchAborts(t *testing.T) {
	zipBytes := makeZip(t, false)
	prefix := t.TempDir()
	zu, _ := ZipURL(PinnedVersion, ArchLinux64)
	du, _ := DigestURL(PinnedVersion, ArchLinux64)
	dl := staticDL{files: map[string][]byte{
		zu: zipBytes,
		du: dgstFile(strings.Repeat("ab", 32)), // wrong digest
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: "Xray x"}}
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("wrong error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, PinnedVersion)); !os.IsNotExist(statErr) {
		t.Error("version dir created despite checksum failure")
	}
}

func TestInstallMissingDgstRejected(t *testing.T) {
	zipBytes := makeZip(t, false)
	prefix := t.TempDir()
	zu, _ := ZipURL(PinnedVersion, ArchLinux64)
	du, _ := DigestURL(PinnedVersion, ArchLinux64)
	dl := staticDL{files: map[string][]byte{
		zu: zipBytes,
		du: []byte("MD5= 00000000000000000000000000000000\nSHA1= 00\n"), // no SHA2-256
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: "Xray x"}}
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("expected rejection of release without SHA2-256")
	}
	if !strings.Contains(err.Error(), "no SHA2-256") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestInstallSmokeCheckFailureCleansUp(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, fe, prefix := installFixture(t, zipBytes)
	fe.versionOut = "not-xray" // smoke check: no "Xray" in output
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("expected smoke failure")
	}
	if !strings.Contains(err.Error(), "smoke") {
		t.Errorf("wrong error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, PinnedVersion)); !os.IsNotExist(statErr) {
		t.Error("version dir left after smoke failure")
	}
	assertNoStageDirs(t, prefix)
}

func TestInstallExistingVersionRefusedWithoutForce(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, _, _ := installFixture(t, zipBytes)
	if _, err := in.Install(PinnedVersion, ArchLinux64, ""); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if _, err := in.Install(PinnedVersion, ArchLinux64, ""); err == nil {
		t.Fatal("second install should be refused")
	}
	in.Force = true
	if _, err := in.Install(PinnedVersion, ArchLinux64, ""); err != nil {
		t.Fatalf("forced reinstall: %v", err)
	}
}

func TestRemoveVersionPrefixGuard(t *testing.T) {
	prefix := t.TempDir()
	in := &Installer{Prefix: prefix}
	// Craft a "version" whose dir would escape the prefix.
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
		if e.IsDir() && strings.HasPrefix(e.Name(), ".xray-stage-") {
			t.Errorf("stale stage dir left behind: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// Zip safety
// ---------------------------------------------------------------------------

func makeZipWithEntry(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, content)
	w2, err := zw.Create("xray")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w2, "FAKE")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipSlipRejected(t *testing.T) {
	for _, evil := range []string{
		"../evil",
		"../../etc/passwd",
		"/absolute/evil",
		"a/../../evil",
	} {
		zipBytes := makeZipWithEntry(t, evil, "x")
		prefix := t.TempDir()
		zu, _ := ZipURL(PinnedVersion, ArchLinux64)
		du, _ := DigestURL(PinnedVersion, ArchLinux64)
		dl := staticDL{files: map[string][]byte{zu: zipBytes, du: dgstFile(dgstFor(t, zipBytes))}}
		in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: "Xray x"}}
		_, err := in.Install(PinnedVersion, ArchLinux64, "")
		if err == nil {
			t.Errorf("zip-slip entry %q accepted", evil)
			continue
		}
		if !strings.Contains(err.Error(), "unsafe") && !strings.Contains(err.Error(), "extraction") {
			t.Errorf("zip-slip %q: wrong error: %v", evil, err)
		}
		// And nothing escaped the prefix.
		if _, statErr := os.Stat(filepath.Join(prefix, "..", "evil")); !os.IsNotExist(statErr) {
			t.Errorf("file escaped prefix for entry %q", evil)
		}
		if _, statErr := os.Stat("/absolute/evil"); !os.IsNotExist(statErr) {
			t.Errorf("file written to absolute path for entry %q", evil)
		}
		assertNoStageDirs(t, prefix)
	}
}

func TestOversizedEntryRejected(t *testing.T) {
	// > 100 MiB single entry (compressed small, inflated huge).
	var big bytes.Buffer
	block := bytes.Repeat([]byte("A"), 1<<20)
	for i := 0; i < 101; i++ {
		big.Write(block)
	}
	zipBytes := makeZipWithEntryCompressed(t, "bomb", big.String())
	prefix := t.TempDir()
	zu, _ := ZipURL(PinnedVersion, ArchLinux64)
	du, _ := DigestURL(PinnedVersion, ArchLinux64)
	dl := staticDL{files: map[string][]byte{zu: zipBytes, du: dgstFile(dgstFor(t, zipBytes))}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: "Xray x"}}
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("oversized entry accepted")
	}
	if !strings.Contains(err.Error(), "unsafe or oversized") {
		t.Errorf("wrong error: %v", err)
	}
	assertNoStageDirs(t, prefix)
}

func makeZipWithEntryCompressed(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, content)
	w2, err := zw.Create("xray")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w2, "FAKE")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// HTTP downloader wiring (local test server; still no external network)
// ---------------------------------------------------------------------------

func TestHTTPDownloaderAgainstLocalServer(t *testing.T) {
	zipBytes := makeZip(t, false)
	sha := dgstFor(t, zipBytes)
	mux := http.NewServeMux()
	mux.HandleFunc("/zip", func(w http.ResponseWriter, r *http.Request) { w.Write(zipBytes) })
	mux.HandleFunc("/dgst", func(w http.ResponseWriter, r *http.Request) { w.Write(dgstFile(sha)) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dl := HTTPDownloader{}
	rc, err := dl.Fetch(srv.URL + "/zip")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(body, zipBytes) {
		t.Error("downloaded body mismatch")
	}
	if _, err := dl.Fetch(srv.URL + "/404"); err == nil {
		t.Error("404 accepted")
	}
}

// ---------------------------------------------------------------------------
// T2 review remediation (docs/reviews/t2-xray-installer-review.md):
// M1 chmod cleanup, M2 gate output excerpt, L1 bounded .dgst
// ---------------------------------------------------------------------------

// M1: a chmod failure after the move must remove the version dir, so
// no poisoned (non-executable) install survives.
func TestInstallChmodFailureCleansUp(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, _, prefix := installFixture(t, zipBytes)
	in.Chmod = func(string, os.FileMode) error { return errors.New("read-only filesystem") }
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("expected chmod failure, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, PinnedVersion)); !os.IsNotExist(statErr) {
		t.Error("version dir left behind after chmod failure")
	}
	assertNoStageDirs(t, prefix)
}

// M2: a rejected config must surface the (bounded) xray output so the
// operator can diagnose WHY the generated config failed the gate.
func TestInstallConfigGateErrorIncludesXrayOutput(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, fe, _ := installFixture(t, zipBytes)
	fe.runTestErr = errors.New("exit status 1")
	fe.runTestOut = "Config error: [Error: dest port 0 out of range]"
	_, err := in.Install(PinnedVersion, ArchLinux64, "/etc/split-tunnel/xray.json")
	if err == nil {
		t.Fatal("expected config-gate failure")
	}
	if !strings.Contains(err.Error(), "dest port 0 out of range") {
		t.Errorf("gate error should include the xray output: %v", err)
	}
}

// M2: the smoke-check error must include the output and must NOT render
// %!v(<nil>) when the process exited 0 but lacked the expected string.
func TestInstallSmokeCheckErrorIncludesOutput(t *testing.T) {
	zipBytes := makeZip(t, false)
	in, fe, _ := installFixture(t, zipBytes)
	fe.versionOut = "something unrelated to xray"
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("expected smoke failure")
	}
	if strings.Contains(err.Error(), "%!v") {
		t.Errorf("nil error rendered into the message: %v", err)
	}
	if !strings.Contains(err.Error(), "something unrelated to xray") {
		t.Errorf("smoke error should include the output: %v", err)
	}
}

// L1: an over-long .dgst sidecar is rejected before any parse/verify.
func TestInstallOversizedDgstRejected(t *testing.T) {
	zipBytes := makeZip(t, false)
	prefix := t.TempDir()
	zu, _ := ZipURL(PinnedVersion, ArchLinux64)
	du, _ := DigestURL(PinnedVersion, ArchLinux64)
	dl := staticDL{files: map[string][]byte{
		zu: zipBytes,
		du: bytes.Repeat([]byte("x"), maxDgstBytes+1),
	}}
	in := &Installer{Prefix: prefix, DL: dl, Exec: &fakeExec{versionOut: "Xray x"}}
	_, err := in.Install(PinnedVersion, ArchLinux64, "")
	if err == nil {
		t.Fatal("expected rejection of oversized .dgst")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestExcerptBounded(t *testing.T) {
	if got := excerpt("xray output"); got != "xray output" {
		t.Errorf("excerpt = %q", got)
	}
	if got := excerpt("  \n "); got != "(no output)" {
		t.Errorf("empty excerpt = %q", got)
	}
	if got := excerpt(strings.Repeat("b", excerptMax+3000)); len(got) > excerptMax+32 || !strings.HasSuffix(got, "... (truncated)") {
		t.Errorf("not bounded: %d bytes", len(got))
	}
}

// mustURL resolves zip or dgst URL for a version (test helper).
func mustURL(t *testing.T, version string, arch Arch, dgst bool) string {
	t.Helper()
	var (
		u   string
		err error
	)
	if dgst {
		u, err = DigestURL(version, arch)
	} else {
		u, err = ZipURL(version, arch)
	}
	if err != nil {
		t.Fatal(err)
	}
	return u
}
