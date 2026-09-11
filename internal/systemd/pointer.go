// pointer.go — the xray "current" binary pointer (design §4.7).
//
// T2 installs Xray into <prefix>/xray/<version>/. The xray unit references
// the VERSION-INDEPENDENT path <prefix>/xray/current/xray, so an xray
// version upgrade is a pointer swap + one service restart — the unit file
// is never rewritten for a version bump (least-restart upgrades).
//
// Swap is atomic: a tmp symlink (current.tmp-<pid>, O_EXCL) is created and
// renamed over "current" (same filesystem — guaranteed). Guards (T3/T4
// pattern):
//
//   - the pointer path, if it exists, must be a SYMLINK (a regular file or
//     directory planted there → refused);
//   - the resolved version target must be a REAL DIRECTORY strictly inside
//     <prefix>/xray/ (symlink-escape and traversal refused);
//   - kind/version are shape-validated (no path separators, version shape
//     vM.m.p) — no shell, no path injection.
//
// `systemctl daemon-reload` is NOT needed for a pointer swap (only unit
// files matter to systemd); the caller (T8) restarts xray-germany.service.
package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// PointerKind is the managed binary pointer kind (currently only xray).
type PointerKind string

const (
	// PointerXray: <prefix>/xray/current → <prefix>/xray/<version>
	PointerXray PointerKind = "xray"
)

// pointerBase returns the pointer directory for a kind
// (<prefix>/<kind>) or an error for an unknown kind.
func pointerBase(kind PointerKind) (string, error) {
	switch kind {
	case PointerXray:
		return binaryPrefix + "/" + string(kind), nil
	default:
		return "", fmt.Errorf("%w: unknown pointer kind %q", ErrSpec, kind)
	}
}

// EnsureBinaryPointer points <prefix>/<kind>/current at
// <prefix>/<kind>/<version>:
//
//   - absent → create;
//   - symlink with the same target → no-op;
//   - different target → tmp symlink (O_EXCL) + atomic rename;
//   - regular file / dir at the pointer path → refused (ErrUnsafeTarget);
//   - version missing / outside the prefix → refused.
func EnsureBinaryPointer(ctx context.Context, kind PointerKind, version string) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	if !versionRE.MatchString(version) {
		return fmt.Errorf("%w: version %q must match vM.m.p", ErrSpec, version)
	}
	base, err := pointerBase(kind)
	if err != nil {
		return err
	}
	pointer := base + "/current"
	target := base + "/" + version

	// The resolved target must be a real directory strictly inside base.
	tst, terr := os.Lstat(target)
	if terr != nil || !tst.IsDir() {
		return fmt.Errorf("%w: version dir %s must exist and be a real directory (install it first)", ErrPreflight, target)
	}
	absTarget, aerr := filepath.Abs(target)
	absBase, berr := filepath.Abs(base)
	if aerr != nil || berr != nil || !stringsHasPrefixSlash(absTarget, absBase) {
		return fmt.Errorf("%w: version dir must resolve inside %s", ErrPreflight, base)
	}

	// Existing pointer: must be a symlink (a planted regular file/dir is
	// refused), then compare targets.
	if st, lerr := os.Lstat(pointer); lerr == nil {
		if st.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%w: %s is a regular file or directory (refusing to replace it)", ErrUnsafeTarget, pointer)
		}
		cur, rerr := os.Readlink(pointer)
		if rerr != nil {
			return fmt.Errorf("%w: cannot read pointer target: %v", ErrPreflight, rerr)
		}
		curAbs, caerr := filepath.Abs(filepath.Join(base, cur))
		if caerr == nil && curAbs == absTarget {
			return nil // same target — no-op
		}
	} else if !os.IsNotExist(lerr) {
		return fmt.Errorf("%w: cannot stat pointer: %v", ErrPreflight, lerr)
	}

	// Atomic swap: tmp symlink O_EXCL, then rename (same fs).
	tmp := pointer + ".tmp-" + strconv.Itoa(os.Getpid())
	if lerr := os.Symlink(target, tmp); lerr != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot create temporary pointer: %v", ErrPreflight, lerr)
	}
	if err := os.Rename(tmp, pointer); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot swap pointer into place: %v", ErrPreflight, err)
	}
	return fsyncDir(base)
}

// stringsHasPrefixSlash reports whether path starts with dir + separator
// (a strictly-inside check without resolving "..").
func stringsHasPrefixSlash(path, dir string) bool {
	return len(path) > len(dir) && path[:len(dir)+1] == dir+string(filepath.Separator)
}
