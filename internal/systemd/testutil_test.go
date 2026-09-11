// testutil_test.go — the shared L1 test harness (design §7).
//
// fakeExec: ordered call log + canned outputs (the xray.Executor fake
// pattern, the entire L2 "fake systemctl shim" tier). redirectPaths:
// repoints every managed-path var at a temp tree (restored on cleanup).
// newTestManager: a ServiceManager with permissive seams so the
// transaction logic runs on any host.
package systemd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// secretMarker is a 64-hex token that satisfies the secret policy
// (mux.ValidateSecretMaterial) yet is DISTINCT from any real deployment
// secret: tests assert its ABSENCE from error strings and journal echoes.
const secretMarker = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

// fakeExec is the test SystemdExecutor: records every call (argv joined
// with spaces) and answers from an ordered/default table.
type fakeExec struct {
	calls   []string
	handler func(argv []string) (string, error)
}

func (f *fakeExec) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.handler != nil {
		return f.handler(args)
	}
	return "", nil
}

func (f *fakeExec) count() int { return len(f.calls) }

// argLine returns the call with argv[0] == prog.
func (f *fakeExec) argLine(prog string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.SplitN(c, " ", 2)[0] == prog {
			out = append(out, c)
		}
	}
	return out
}

// countOf counts calls whose argv starts with prog.
func (f *fakeExec) countOf(prog string) int { return len(f.argLine(prog)) }

// has reports whether some call equals s exactly (argv joined by spaces).
func (f *fakeExec) has(s string) bool {
	for _, c := range f.calls {
		if c == s {
			return true
		}
	}
	return false
}

// redirectPaths repoints the managed-path vars at fresh temp subdirs and
// restores all of them (plus nowUnixNano and rootCheck) on cleanup.
// The temp layout mirrors the production tree:
//
//	tmp/
//	  unit/            (= unitDir)
//	  unit/multi-user.target.wants/ (= wantsDir)
//	  state/           (= stateDir)
//	  state/units-backup/           (= unitsBackupDir)
//	  log/             (= logDir)
//	  data/            (= dataDir)
//	  bin/             (= binaryPrefix)
func redirectPaths(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()

	unit := filepath.Join(root, "unit")
	wants := filepath.Join(unit, "multi-user.target.wants")
	state := filepath.Join(root, "state")
	unitsBackup := filepath.Join(state, "units-backup")
	log := filepath.Join(root, "log")
	data := filepath.Join(root, "data")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{unit, wants, state, unitsBackup, log, data, bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	unitDir = unit
	wantsDir = wants
	stateDir = state
	unitsBackupDir = unitsBackup
	logDir = log
	dataDir = data
	binaryPrefix = bin

	oldNow := nowUnixNano
	step := 0
	nowUnixNano = func() int64 {
		step++
		return 1_000_000 + int64(step)*1_000_000
	}
	oldRoot := rootCheck
	rootCheck = func() error { return nil }

	t.Cleanup(func() {
		unitDir = UnitDir
		wantsDir = WantsDir
		stateDir = StateDir
		unitsBackupDir = UnitsBackupDir
		logDir = LogDir
		dataDir = DataDir
		binaryPrefix = BinaryPrefix
		nowUnixNano = oldNow
		rootCheck = oldRoot
	})
	return root
}

// newTestManager builds a ServiceManager over ex with permissive OS seams:
// no root error, no live pids, and every file treated as root-owned (the
// owner bit does not exist on non-Linux hosts; on Linux the fixtures are
// created by the test user and the permissive seam stands in for root —
// the permission CHAIN itself is asserted by perms_test.go, Linux+root).
func newTestManager(ex SystemdExecutor) *ServiceManager {
	m := NewServiceManager(ex)
	m.RootCheck = func() error { return nil }
	m.PidAlive = func(int) bool { return false }
	m.rootOwner = func(os.FileInfo) bool { return true }
	return m
}

// validEnvKV returns a minimal, fully-valid env state for a role.
func validEnvKV(t *testing.T, role Role) map[string]string {
	t.Helper()
	switch role {
	case RoleGermany:
		return map[string]string{
			config.EnvUpWsUrl:    "ws://127.0.0.1:9001/upload",
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     secretMarker,
		}
	case RoleIran:
		return map[string]string{
			config.EnvSocksListen: "127.0.0.1:10900",
			config.EnvWsListen:    "127.0.0.1:9001",
			config.EnvDownCarrier: "127.0.0.1:9002",
			config.EnvSecret:      secretMarker,
		}
	default:
		t.Fatalf("unexpected role %q", role)
	}
	return nil
}

// sha256hex of data.
func sha256hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// okHandler is the default canned-output table: is-active → "active",
// everything else → empty success. Tests that need a failing step
// override the handler and fall through to this table for the rest.
func okHandler(args []string) (string, error) {
	if len(args) >= 2 && args[0] == "systemctl" && args[1] == "is-active" {
		return "active", nil
	}
	return "", nil
}

// writeRaw writes data to path (0644) without the crash-safe writer —
// test fixture planting only.
func writeRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
