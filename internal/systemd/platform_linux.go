// platform_linux.go — Linux-only OS defaults (the deployment target).
//
// These are the production implementations of the seams that differ per
// platform: numeric uid extraction, NSS user/group lookup, the root check
// (euid) and pid liveness (/proc). The non-Linux counterpart fails closed
// (see platform_other.go) — the product targets Linux; the fakes keep L1
// tests cross-platform.
//go:build linux

package systemd

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// uidOf extracts the numeric owner uid from a Linux stat.Sys()
// (*syscall.Stat_t). Returns -1 when the shape is unexpected.
func uidOf(sys any) int {
	st, ok := sys.(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}

// lookupUserUID resolves a user name to its numeric uid via NSS (os/user
// — stdlib, no shell).
func lookupUserUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, err
	}
	return n, nil
}

// lookupGroupGID resolves a group name to its numeric gid via NSS.
func lookupGroupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, err
	}
	return n, nil
}

// defaultRootCheck: root iff euid == 0.
func defaultRootCheck() error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	return nil
}

// defaultPidAlive: a pid is alive iff /proc/<pid>/stat exists.
func defaultPidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Lstat("/proc/" + strconv.Itoa(pid) + "/stat")
	return err == nil
}

// fsyncDir fsyncs a directory (durability of renames/creates). Linux is
// the deployment target, so the real durability barrier applies here.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
