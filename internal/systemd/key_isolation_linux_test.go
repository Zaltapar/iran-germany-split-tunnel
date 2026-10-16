//go:build linux

package systemd

// key_isolation_linux_test.go — C5 D3 key-isolation, the real
// mode/owner + uid-exclusion facts, end-to-end through the repo's own
// writer path (xray activation write, then EnsureStateDir convergence).
//
// Linux + root only: the facts being asserted are Unix owner/group and
// process uid separation, which do not exist on the Windows dev host.
//
// What it proves:
//   1. The Germany config written with a SYNTHETIC private key, through the
//      repo's own activation writer path (xray.ActivateGermanyConfig: 0600
//      candidate + fsync + gate + atomic swap) and then converged by
//      EnsureStateDir, ends up 0640 root:split-tunnel-xray — group-excluded
//      from the dashboard's split-tunnel group and world-excluded (no o-*).
//   2. The dashboard process user (split-tunnel, primary group split-tunnel,
//      NOT a member of the key group) CANNOT read the key config, but CAN
//      read a service-group config (Caddyfile). This is the in-repo
//      expression of "the tunneldash unit cannot read that path" as far as
//      uid/group separation allows (systemd's SupplementaryGroups= only
//      applies inside the xray unit's exec context, so a plain shell check
//      as split-tunnel is the correct model of a dashboard compromise).

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// c5FakeXray is a no-op xray.Executor so the activation writer path runs the
// full tmp+fsync+gate+swap sequence against a temp tree without a real binary.
type c5FakeXray struct{}

func (c5FakeXray) VersionOutput(string) (string, error) { return "Xray 26.3.27", nil }
func (c5FakeXray) Keypair(string) (string, error)       { return "", nil }
func (c5FakeXray) RunTest(string, string) (string, error) {
	return "ok", nil
}

// syntheticKeypair builds a strictly-decodable 32-byte X25519-shaped keypair
// (RawURL base64) so xray.checkKeypair accepts it. It is a fixed, non-
// production vector — no real key material.
func syntheticKeypair() *xray.Keypair {
	priv := make([]byte, 32)
	pub := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i)
		pub[i] = byte(i + 1)
	}
	return &xray.Keypair{
		PrivateRaw: base64.RawURLEncoding.EncodeToString(priv),
		PublicRaw:  base64.RawURLEncoding.EncodeToString(pub),
	}
}

func TestC5KeyIsolationEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for real chown + runuser uid separation")
	}
	root := redirectPaths(t)
	if _, err := user.Lookup(ServiceUser); err != nil {
		t.Skipf("service user %q unavailable: %v", ServiceUser, err)
	}
	// Make the whole path chain from the service account to the files
	// traversable. Go's t.TempDir() nests the returned path under a
	// per-test scratch dir (e.g. /tmp/TestXxx<id>/001) that is 0700
	// root:root. The service-account read check
	// (runuser -u split-tunnel -- test -r <path>) requires execute on
	// EVERY ancestor. In production the files live under /etc (0755),
	// so these scratch layers don't exist there; without opening them
	// up the chain fails for reasons unrelated to the convergence logic
	// under test. Walk up from the temp root to (but not including)
	// /tmp and make each intermediate dir 0755.
	for d := root; ; {
		if d == "/tmp" || d == "/" {
			break
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if np := filepath.Dir(d); np == d {
			break
		} else {
			d = np
		}
	}
	// Provision the key group through the repo's own writer path first —
	// this is what the deploy adapter does (LinuxAdapter.Prepare). Idempotent.
	if err := EnsureKeyGroup(context.Background(), OSExecutor{}); err != nil {
		t.Fatalf("EnsureKeyGroup (provision the split-tunnel-xray group): %v", err)
	}
	if _, err := user.LookupGroup(XrayKeyGroup); err != nil {
		t.Skipf("key group %q not provisioned and EnsureKeyGroup could not create it: %v", XrayKeyGroup, err)
	}

	// Open the state dir 0750 root:service-group exactly as EnsureStateDir
	// would, then write the live key config through the repo's OWN writer
	// path: xray activation (0600 candidate + gate + swap).
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	params := xray.RealityParams{
		SNI:     "camouflage.example",
		ShortID: "0123456789abcdef",
		UUID:    "8e7d6c5b-4a3f-4e2d-9c8b-7a6f5e4d3c2b",
	}
	_, err := xray.ActivateGermanyConfig(xray.ActivateParams{
		Params:   params,
		Keypair:  syntheticKeypair(),
		Dir:      stateDir,
		FileName: "xray-germany.json",
		Bin:      "/opt/split-tunnel/xray/current/xray",
		Exec:     c5FakeXray{},
	})
	if err != nil {
		t.Fatalf("activate through the repo writer path: %v", err)
	}
	// The activation writes 0600 root:root (the pre-C5 state T3 leaves
	// behind). Now converge through the repo's own convergence writer path.
	if err := EnsureStateDir(context.Background()); err != nil {
		t.Fatalf("EnsureStateDir (the C5 convergence): %v", err)
	}

	keyPath := stateDir + "/xray-germany.json"
	assertC5KeyFileModeOwner(t, keyPath)

	// A service-group config (no key) must stay readable by the service
	// group, so the other service-group processes that legitimately read
	// Caddyfile / xray-consumer.json are unaffected.
	if err := os.WriteFile(stateDir+"/Caddyfile", []byte(":443\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDir(context.Background()); err != nil {
		t.Fatalf("re-converge: %v", err)
	}

	// uid separation: the dashboard's user (split-tunnel, primary group
	// split-tunnel, NOT in the key group) cannot read the key config, but
	// can read a service-group config.
	if err := runAsServiceGroupMustDeny(keyPath); err != nil {
		t.Fatalf("dashboard uid CAN read the key config %s — isolation broken: %v", keyPath, err)
	}
	if err := runAsServiceGroupCanRead(stateDir + "/Caddyfile"); err != nil {
		t.Fatalf("service-group config unexpectedly unreadable by %s: %v", ServiceUser, err)
	}
}

// assertC5KeyFileModeOwner checks the key config is exactly 0640, root-owned,
// and group-owned by XrayKeyGroup (the dashboard group and world are both
// excluded by the 0640 bits; the dashboard group is excluded by group
// ownership).
func assertC5KeyFileModeOwner(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skipf("%s has unexpected stat type (non-Linux)", path)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("key config %s mode=%o, want 0640 (no world bit; group = key group only)", path, st.Mode().Perm())
	}
	if sys.Uid != 0 {
		t.Fatalf("key config owner uid=%d, want root (0)", sys.Uid)
	}
	keyGid, err := lookupGroupGID(XrayKeyGroup)
	if err != nil {
		t.Fatalf("key group %q unresolvable: %v", XrayKeyGroup, err)
	}
	if int(sys.Gid) != keyGid {
		t.Fatalf("key config group gid=%d, want %s (gid %d) — the dashboard group must be excluded", sys.Gid, XrayKeyGroup, keyGid)
	}
}

// runAsServiceGroupCanRead reports an error if the service user CANNOT read
// path (the control case: a key-free service-group config must stay
// readable).
func runAsServiceGroupCanRead(path string) error {
	return exec.Command("runuser", "-u", ServiceUser, "--", "test", "-r", path).Run()
}

// runAsServiceGroupMustDeny reports an error when the service user CAN read
// path — i.e., the C5 isolation is broken. It succeeds (nil) when the read is
// correctly denied.
func runAsServiceGroupMustDeny(path string) error {
	err := exec.Command("runuser", "-u", ServiceUser, "--", "test", "-r", path).Run()
	if err == nil {
		return errors.New("service user was able to read the key config")
	}
	return nil
}
