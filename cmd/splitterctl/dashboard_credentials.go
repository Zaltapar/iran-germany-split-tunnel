// dashboard_credentials.go — the `rotate-dashboard-credentials`
// subcommand: idempotent, root-only provisioning of the Tunneldash
// Basic-auth PBKDF2-HMAC-SHA256 verifier, plus a root-only plaintext
// retrieval file so the operator can recover the actual username +
// password over SSH without the value ever appearing in installer
// stdout, argv, env, or shell history.
//
// On-disk layout (mirrors the installer's D1a directory traversal):
//
//	/etc/split-tunnel/dashboard/            0750 root:split-tunnel
//	/etc/split-tunnel/dashboard/credentials        0640 root:split-tunnel
//	    -> single-line PBKDF2 verifier JSON; what SPLIT_TUNNELDASH_CREDENTIALS
//	       names. The tunneldash service reads THIS file (group-readable).
//	/etc/split-tunnel/dashboard/credentials.recovery  0600 root:root
//	    -> "admin <password>" plaintext. Written ONLY at generation/rotation.
//	       NOT referenced by the service; it exists purely so the operator
//	       can `sudo cat` it to retrieve the actual credential. Delete it
//	       after retrieval if the host should hold no plaintext at rest.
//
// Command shape (errors name fields, never values):
//
//	rotate-dashboard-credentials [ --fresh | --if-missing | --recover <dir> ]
//
// Behaviour:
//   - no flag (idempotent): if `credentials` does not exist, generate a new
//     (admin, 128-bit) pair, write the verifier (0640 root:split-tunnel) and
//     the retrieval file (0600 root:root); if it already exists, preserve
//     both untouched and print nothing secret. Re-running is safe.
//   - --if-missing: provision only when the verifier is absent. This is the
//     one-click installer's idempotent path: a re-run NEVER overwrites an
//     existing credential (the installer separately requires an explicit
//     --fresh to rotate).
//   - --fresh: explicitly rotate. Replaces the verifier, generates a new
//     password, and overwrites the retrieval file (no stale credential left
//     behind).
//   - --recover <dir>: re-derive a missing `credentials` verifier from a
//     carried retrieval file (<dir>/credentials.recovery, the "admin <pass>"
//     plaintext the operator saved out-of-band). This is the "I lost the
//     verifier file" restore path; it does NOT rotate.
//
// Output contract (matches the rest of the CLI): the 128-bit password, the
// 16-byte salt, and the 32-byte digest are NEVER printed to stdout, the
// journal, or argv. The command prints file PATHS only and tells the
// operator to `sudo cat` the 0600 retrieval file to obtain the credential.
//
// Root + Linux only: same gate as `install-extra tunneldash`.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/dashboard"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// Canonical on-disk locations. Referenced by PATH only; the verifier value
// and the password value are never part of env wiring or logs. These are
// package vars (not consts) so _test.go files can point the provisioning
// paths at a temporary root without touching the production /etc tree.
var (
	dashCredsFile     = "/etc/split-tunnel/dashboard/credentials"
	dashRetrievalFile = "/etc/split-tunnel/dashboard/credentials.recovery"
	dashCredsDir      = "/etc/split-tunnel/dashboard"
)

// convergeCredDir is the directory-convergence step (systemd.ConvergeRootGroup:
// 0750 root:split-tunnel) behind the generate/recover flows. It is a var (like
// goos/rootCheck) so _test.go files can point the flows at a temp dir without
// the root/systemd gate; production always converges the real /etc dir.
var convergeCredDir = func(dir string) error {
	return systemd.ConvergeRootGroup(context.Background(), dir, 0o750)
}

// rotateDashboardCredentialsCommand is the `splitterctl
// rotate-dashboard-credentials` entrypoint. It accepts at most one of
// --fresh or --recover <dir>.
func rotateDashboardCredentialsCommand(ctx context.Context, out io.Writer, args []string) error {
	if err := requireLinux("rotate-dashboard-credentials"); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("rotate-dashboard-credentials: requires root (euid=%d); the layout is 0640 root:split-tunnel + 0600 root:root", os.Geteuid())
	}

	fresh := false
	ifMissing := false
	recoverDir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--fresh":
			fresh = true
		case "--if-missing":
			ifMissing = true
		case "--recover":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return fmt.Errorf("%w: --recover requires a non-empty directory", errUsage)
			}
			recoverDir = args[i]
		default:
			return fmt.Errorf("%w: rotate-dashboard-credentials accepts at most one of [--fresh] [--if-missing] [--recover <dir>]", errUsage)
		}
	}
	if fresh && (recoverDir != "" || ifMissing) {
		return fmt.Errorf("%w: --fresh is mutually exclusive with --if-missing and --recover", errUsage)
	}
	if recoverDir != "" && ifMissing {
		return fmt.Errorf("%w: --recover is mutually exclusive with --if-missing", errUsage)
	}

	switch {
	case recoverDir != "":
		return rotateRecover(out, dashCredsDir, recoverDir)
	case fresh:
		// Explicit rotation: always (re)generate, overwriting any existing
		// credential. The operator's deliberate "rotate now" action.
		return rotateGenerate(out, dashCredsDir, true)
	case ifMissing:
		// One-click installer's idempotent path: generate only when the
		// verifier is absent, otherwise preserve (never rotate). This is
		// the "re-run the installer" behaviour that keeps existing
		// credentials alive.
		return rotateIfMissing(out, dashCredsDir)
	default:
		// Bare invocation is treated as --if-missing for safety: an
		// operator who wants to rotate must pass --fresh explicitly, so
		// a re-run can never silently destroy the live credential.
		return rotateIfMissing(out, dashCredsDir)
	}
}

// rotateIfMissing preserves an existing verifier + retrieval file untouched;
// generates both (and only both) when the verifier is absent. This is the
// idempotent path the one-click installer invokes on every re-run.
func rotateIfMissing(out io.Writer, dir string) error {
	creds := filepath.Join(dir, filepath.Base(dashCredsFile))
	if fileExistsRegular(creds) {
		_, _ = fmt.Fprintf(out, "rotate-dashboard-credentials: %s already present; preserved as-is (run with --fresh to rotate, or --recover <dir> to re-derive a lost verifier from a carried retrieval file)\n", creds)
		_, _ = fmt.Fprintf(out, "retrieve the actual username + password with: sudo cat %s   (0600 root:root; delete after retrieval if the host should hold no plaintext at rest)\n", filepath.Join(dir, filepath.Base(dashRetrievalFile)))
		return nil
	}
	_, _ = fmt.Fprintln(out, "rotate-dashboard-credentials: no existing verifier; generating a fresh one")
	return rotateGenerate(out, dir, false)
}

// rotateGenerate (re)generates the (admin, 128-bit) pair, writes the PBKDF2
// verifier (0640 root:split-tunnel) and the plaintext retrieval file (0600
// root:root). `explicit` distinguishes a fresh rotation from an idempotent
// first-run in the log verb only. No credential value is ever printed.
func rotateGenerate(out io.Writer, dir string, explicit bool) error {
	if err := convergeCredDir(dir); err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: converge %s: %w", dir, err)
	}
	pass, err := dashboard.GenerateBasicAuthPassword()
	if err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: generate password: %w", err)
	}
	ver, err := dashboard.HashBasicAuthPassword(dashboard.DefaultBasicAuthUsername, pass)
	if err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: hash: %w", err)
	}
	creds := filepath.Join(dir, filepath.Base(dashCredsFile))
	// The service reads the salted verifier, group-readable.
	if err := writeSecretFile(creds, ver, 0o640, "root", systemd.ServiceGroup); err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: write %s: %w", creds, err)
	}
	// The operator-only plaintext retrieval file: root:root, 0600, so it is
	// NOT in the tunneldash group and never read by the service.
	retrieval := dashboard.DefaultBasicAuthUsername + " " + pass + "\n"
	ret := filepath.Join(dir, filepath.Base(dashRetrievalFile))
	if err := writeSecretFile(ret, retrieval, 0o600, "root", "root"); err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: write %s: %w", ret, err)
	}

	verb := "rotated"
	if !explicit {
		verb = "generated"
	}
	_, _ = fmt.Fprintf(out, "rotate-dashboard-credentials: %s Basic-auth verifier -> %s (0640 root:split-tunnel; PBKDF2 salted digest, value never printed)\n", verb, creds)
	_, _ = fmt.Fprintf(out, "rotate-dashboard-credentials: %s root-only retrieval file -> %s (0600 root:root, not read by the service; delete after retrieval)\n", verb, ret)
	_, _ = fmt.Fprintf(out, "retrieve the actual username + password with: sudo cat %s\n", ret)
	return nil
}

// rotateRecover re-derives a missing `credentials` verifier from a carried
// retrieval file (<dir>/credentials.recovery, the "admin <pass>" plaintext).
// It writes only the verifier; it does NOT rewrite the retrieval file or
// rotate. This is the "I lost the verifier" restore path.
func rotateRecover(out io.Writer, dir string, recoverDir string) error {
	if err := convergeCredDir(dir); err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: converge %s: %w", dir, err)
	}
	src := filepath.Join(recoverDir, filepath.Base(dashRetrievalFile))
	if !fileExistsRegular(src) {
		return fmt.Errorf("rotate-dashboard-credentials: --recover %q: %s is not a regular file", recoverDir, src)
	}
	user_, pass, ok := parseRetrievalFile(stringMust(src))
	if !ok {
		return fmt.Errorf("rotate-dashboard-credentials: %s is not a valid retrieval file (expected a single \"<user> <password>\" line)", src)
	}
	ver, err := dashboard.HashBasicAuthPassword(user_, pass)
	if err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: hash: %w", err)
	}
	creds := filepath.Join(dir, filepath.Base(dashCredsFile))
	if err := writeSecretFile(creds, ver, 0o640, "root", systemd.ServiceGroup); err != nil {
		return fmt.Errorf("rotate-dashboard-credentials: write %s: %w", creds, err)
	}
	_, _ = fmt.Fprintf(out, "rotate-dashboard-credentials: re-derived %s from %s (user=%q; verifier only — the retrieval file itself was NOT modified or re-printed)\n", creds, src, user_)
	return nil
}

// --- helpers ---------------------------------------------------------------

// fileExistsRegular reports whether p is an existing regular file.
func fileExistsRegular(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// stringMust reads a file's contents as a trimmed string. The caller has
// already confirmed the path is a regular file; a read error is fatal to the
// recover flow and is reported by the caller's wrap.
func stringMust(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseRetrievalFile parses the root-only retrieval file written by
// rotateGenerate. On-disk format (documented so the operator can hand-edit
// a carried copy):
//
//	<user> <password>\n
//
// where <user> is the single space-free username (DefaultBasicAuthUsername
// "admin") and <password> is the 32-lowercase-hex string produced by
// GenerateBasicAuthPassword (16 random bytes, hex-encoded). The delimiter is
// the FIRST run of whitespace (space or tab); everything after it,
// re-trimmed of leading whitespace, is the password. Because the generated
// password is pure hex it never contains whitespace, so the split is
// unambiguous. Only a SINGLE non-empty line is accepted; leading/trailing
// blank lines are tolerated (TrimSpace), but two non-empty lines, a missing
// delimiter, or an empty user/password are rejected (ok == false).
//
// Whitespace behavior is explicit: surrounding blank lines / trailing newline
// are stripped; internal whitespace in the password is preserved, but a
// whitespace-only password is rejected.
func parseRetrievalFile(content string) (string, string, bool) {
	lines := strings.Split(content, "\n")
	var nonEmpty []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			nonEmpty = append(nonEmpty, strings.TrimSpace(l))
		}
	}
	if len(nonEmpty) != 1 {
		return "", "", false
	}
	sp := strings.IndexAny(nonEmpty[0], " \t")
	if sp <= 0 || sp == len(nonEmpty[0]) {
		return "", "", false
	}
	user_ := nonEmpty[0][:sp]
	pass := strings.TrimLeft(nonEmpty[0][sp:], " \t")
	if user_ == "" || pass == "" {
		return "", "", false
	}
	return user_, pass, true
}

// writeSecretFile writes data to path atomically (tmp + fsync + chown +
// rename + dir fsync) with the given mode and ownership. The ownership is
// converged on the TEMP file BEFORE the atomic rename so a chown failure can
// never publish a final file with the wrong owner. On Linux the chown is
// authoritative; on a dev host (non-Linux) only the chmod applies so the
// layout stays exercisable. data already ends with its own newline only when
// the caller supplied it; we do not add one here (callers are explicit).
func writeSecretFile(path, data string, mode os.FileMode, ownUser, group string) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	// O_EXCL guarantees the temp name is brand-new (never follows a planted
	// symlink at the tmp path); O_TRUNC is redundant with O_CREATE|O_EXCL.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if _, err := f.WriteString(data); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	// Ownership must be correct on the inode BEFORE it becomes the live
	// path: a wrong-owner final file is worse than a missing one.
	if runtime.GOOS == "linux" {
		if err := chownFn(tmp, ownUser, group); err != nil {
			cleanup()
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	if d, derr := os.Open(dir); derr == nil { // durability of the rename.
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// chownByName resolves user + group names to uids/gids via NSS (os/user —
// stdlib, no shell) and applies os.Chown. An unresolvable group is a hard
// error (fail closed), matching the systemd user-provisioning contract.
// chownFn is a var (like convergeCredDir) so _test.go files can simulate a
// chown failure and prove the temp file is removed and never renamed into
// place; production always uses chownByName.
var chownFn = chownByName

func chownByName(path, ownUser, group string) error {
	u, err := user.Lookup(ownUser)
	if err != nil {
		return fmt.Errorf("resolve user %q: %w", ownUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid for %q: %w", ownUser, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("resolve group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for %q: %w", group, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}
