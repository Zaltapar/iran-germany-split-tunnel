// platform_other.go — fail-closed OS defaults for non-Linux hosts.
//
// The product deploys to Linux only (design §6: "OS-level defaults are
// Linux-gated (runtime.GOOS == \"linux\" — the target platform); the fakes
// keep L1 fully cross-platform on the Windows dev host"). The pure parts of
// the package (RenderUnit, validation, the apply transaction with an
// injected executor) compile and run everywhere; these OS-default seams
// refuse instead of guessing.
//go:build !linux

package systemd

import (
	"errors"
)

// uidOf: no Stat_t shape on non-Linux — -1 (treat as not root-owned).
func uidOf(any) int { return -1 }

// lookupUserUID / lookupGroupGID: NSS is unavailable — refuse.
func lookupUserUID(name string) (int, error) {
	return -1, errors.New("user lookup is Linux-only (target platform)")
}

func lookupGroupGID(name string) (int, error) {
	return -1, errors.New("group lookup is Linux-only (target platform)")
}

// defaultRootCheck: the only cross-platform euid notion is 0 on Unix; on
// non-Linux hosts refuse (a Windows dev host must not claim root).
func defaultRootCheck() error { return ErrNotRoot }

// defaultPidAlive: /proc is Linux-only; refuse (fail closed) — the
// injected fakes supply liveness for tests on any host.
func defaultPidAlive(int) bool { return false }

// fsyncDir: directory fsync is a Linux durability concept (rename/creat
// barriers on the journal). Non-Linux dev hosts have no equivalent; the
// no-op keeps L1 tests cross-platform on the Windows dev host while the
// real barrier applies on the Linux deployment target.
func fsyncDir(string) error { return nil }
