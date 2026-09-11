// user.go — service user and directory provisioning (design §4.8).
//
// Permission chain (CRITICAL-1, the finding that nearly shipped a
// non-root xray that could not read its own config):
//
//	/etc/split-tunnel            0750 root:split-tunnel   (service group enters)
//	  xray-germany.json (live)   0640 root:split-tunnel   (service group reads)
//	  Caddyfile (live)           0640 root:split-tunnel   (service group reads)
//	  *.prev / *.tmp (rollback)  0600 root:root           (private keys — root only)
//	  <role>.env                 0600 root:root           (systemd reads as root
//	                                                   before Setuid — staging)
//	/var/log/split-tunnel        0775 root:split-tunnel   (service group writes
//	                                                   — it creates its own error log)
//	/var/lib/split-tunnel        0755 split-tunnel:split-tunnel (Caddy ACME)
//
// T3 (internal/xray) rewrites the live config 0600 root:root on every
// (re)activation, so the deploy layer (T8) MUST re-run EnsureStateDir after
// every activation and before xray ApplyUnit/restart. This is documented in
// the T8 contract and covered by test 18 (permission-chain convergence).
//
// All directory mutations are Linux-gated (chown is the mechanism); on
// other hosts the functions fail with a clear error rather than doing a
// half-correct job. uid/gid resolution uses os/user (stdlib, NSS) — no
// shell, no injection surface. Tests use temp-dir analogs where possible.
package systemd

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// User/directory fixed attributes (design §4.8 — not caller inputs).
const (
	userShell   = "/usr/sbin/nologin"
	userHome    = "/nonexistent"
	userComment = "split-tunnel service user"
)

// EnsureUser creates the split-tunnel system user if absent. Idempotent:
// an existing user is NEVER mutated (auto-modifying user state is not
// reversible — a conflicting shell/group is reported by the doctor, T7).
//
// Exact useradd args (asserted by tests):
//
//	useradd --system --group --shell /usr/sbin/nologin --home-dir
//	/nonexistent --comment "split-tunnel service user" split-tunnel
func EnsureUser(ctx context.Context, ex SystemdExecutor) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	if ex == nil {
		return fmt.Errorf("%w: executor is nil", ErrSpec)
	}
	if _, err := ex.Run(ctx, "id", "-u", ServiceUser); err == nil {
		return nil // exists — no-op, never mutated
	}
	if _, cerr := ex.Run(ctx, "useradd", "--system", "--group",
		"--shell", userShell,
		"--home-dir", userHome,
		"--comment", userComment,
		ServiceUser); cerr != nil {
		return fmt.Errorf("%w: useradd %s: %v", ErrPreflight, ServiceUser, cerr)
	}
	return nil
}

// liveStateFiles are the state-dir files the service group must be able to
// READ (converged to 0640 root:split-tunnel). Rollback artifacts (.prev /
// .tmp) are deliberately NOT here — they contain previous private keys and
// stay 0600 root:root.
var liveStateFiles = []string{"xray-germany.json", "Caddyfile"}

// EnsureStateDir converges /etc/split-tunnel to 0750 root:split-tunnel and
// the live service-readable configs to 0640 root:split-tunnel. Idempotent;
// safe (and required) to call after every T3 activation.
//
// Refusals (fail closed): the path exists as a symlink, or it exists but is
// not root-owned (we never take over a foreign directory).
func EnsureStateDir(ctx context.Context) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	if err := ensureDir(stateDir, 0o750, false); err != nil {
		return err
	}
	// Converge the live configs the service group must read.
	for _, name := range liveStateFiles {
		p := stateDir + "/" + name
		st, lerr := os.Lstat(p)
		if lerr != nil {
			if os.IsNotExist(lerr) {
				continue // not installed yet
			}
			return fmt.Errorf("%w: cannot stat %s: %v", ErrPreflight, p, lerr)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink (refusing)", ErrUnsafeTarget, p)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrPreflight, p)
		}
		if !isRootOwned(st) {
			return fmt.Errorf("%w: %s is not root-owned (refusing)", ErrPreflight, p)
		}
		if err := chownRootGroup(p); err != nil {
			return fmt.Errorf("%w: chown %s: %v", ErrPreflight, p, err)
		}
		if err := os.Chmod(p, 0o640); err != nil {
			return fmt.Errorf("%w: chmod %s: %v", ErrPreflight, p, err)
		}
	}
	return fsyncDir(stateDir)
}

// EnsureLogDir converges /var/log/split-tunnel to 0775 root:split-tunnel.
// The group write bit is MANDATORY: xray creates its own error-log file
// there (path from the T3 golden config); 0755 would break the unit.
//
// ex is part of the T8 contract (interface symmetry with EnsureUser);
// directory operations are in-process (os) and do not shell out.
func EnsureLogDir(ctx context.Context, ex SystemdExecutor) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	return ensureDir(logDir, 0o775, false)
}

// EnsureDataDir converges /var/lib/split-tunnel to 0755
// split-tunnel:split-tunnel (Caddy ACME storage via XDG_DATA_HOME). Only
// needed for the iran origin unit.
//
// ex is part of the T8 contract (interface symmetry with EnsureUser);
// directory operations are in-process (os) and do not shell out.
func EnsureDataDir(ctx context.Context, ex SystemdExecutor) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	return ensureDir(dataDir, 0o755, true)
}

// ensureDir creates dir (when absent) with perm and converges ownership:
// ownedByService=false → root:split-tunnel; true → split-tunnel:split-tunnel.
// Existing dirs must be real (no symlink) and, for root-owned targets,
// root-owned (we never take over a foreign directory).
func ensureDir(dir string, perm os.FileMode, ownedByService bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w: directory provisioning is Linux-only (target platform)", ErrSpec)
	}
	st, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.Mkdir(dir, perm); err != nil {
			return fmt.Errorf("%w: cannot create %s: %v", ErrPreflight, dir, err)
		}
	case err != nil:
		return fmt.Errorf("%w: cannot stat %s: %v", ErrPreflight, dir, err)
	case st.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is a symlink (refusing)", ErrUnsafeTarget, dir)
	case !st.IsDir():
		return fmt.Errorf("%w: %s is not a directory", ErrPreflight, dir)
	}
	if ownedByService {
		if err := chownService(dir); err != nil {
			return fmt.Errorf("%w: chown %s: %v", ErrPreflight, dir, err)
		}
	} else {
		if st, rerr := os.Stat(dir); rerr != nil || !isRootOwned(st) {
			return fmt.Errorf("%w: %s is not root-owned (refusing to take over a foreign directory)", ErrPreflight, dir)
		}
		if err := chownRootGroup(dir); err != nil {
			return fmt.Errorf("%w: chown %s: %v", ErrPreflight, dir, err)
		}
	}
	if err := os.Chmod(dir, perm); err != nil {
		return fmt.Errorf("%w: chmod %s: %v", ErrPreflight, dir, err)
	}
	return nil
}

// isRootOwned reports whether st's owner UID is 0.
func isRootOwned(st os.FileInfo) bool { return st.Sys() != nil && uidOf(st.Sys()) == 0 }

// chownRootGroup chowns path to root:split-tunnel.
func chownRootGroup(path string) error {
	gid, err := lookupGroupGID(ServiceGroup)
	if err != nil {
		return fmt.Errorf("group %s: %v", ServiceGroup, err)
	}
	return os.Chown(path, 0, gid)
}

// chownService chowns path to split-tunnel:split-tunnel.
func chownService(path string) error {
	uid, err := lookupUserUID(ServiceUser)
	if err != nil {
		return fmt.Errorf("user %s: %v", ServiceUser, err)
	}
	gid, err := lookupGroupGID(ServiceGroup)
	if err != nil {
		return fmt.Errorf("group %s: %v", ServiceGroup, err)
	}
	return os.Chown(path, uid, gid)
}
