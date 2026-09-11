// envfile.go — D4 env-file management (design §4.4/§4.5).
//
// The tunnel secret (and every other runtime value) lives ONLY in the
// 0600 root:root env file that systemd reads as root BEFORE dropping
// privileges — never in a unit file (proven pattern on staging). The unit
// renderer structurally cannot emit value-carrying Environment= lines for
// splitter units.
//
// Validation is the existing authoritative validator: the kv map is folded
// into a config.Config (starting from config.Defaults()) and passed to
// config.Validate(role). T5 re-declares no env-name strings and no
// validation rules — the config.Env* constants are the single source of
// truth for key names.
//
// Hygiene: values are never echoed in errors (field-only), values may not
// contain newlines/CR, leading '#' (comment injection) or be empty, and
// the rendered file is LF with a single trailing newline, in a fixed key
// order so equal state renders equal bytes (idempotence).
package systemd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// envFileMaxBackups: keep the latest N managed env-file backups.
const envFileMaxBackups = 3

// requiredEnvKeys per role: the keys that MUST be present in the kv map
// (the deployment's essential state; the code defaults are placeholders
// that fail validation, so a missing key would never silently "work").
var requiredEnvKeys = map[Role][]string{
	RoleGermany: {config.EnvUpWsUrl, config.EnvDownListen, config.EnvSecret},
	RoleIran:    {config.EnvSocksListen, config.EnvWsListen, config.EnvDownCarrier, config.EnvSecret},
}

// optionalEnvKeys: tuning knobs, written only when the caller supplies a
// non-empty value. Names come from the config constants (no redeclaration).
var optionalEnvKeys = []string{
	config.EnvMetricsPort,
	config.EnvAllowWeak,
	config.EnvRelayBuf,
	config.EnvQueueBytes,
	config.EnvQueueFrames,
	config.EnvQueueTotal,
	config.EnvOverflowMs,
	config.EnvCarrierGrace,
	config.EnvBootstrapWait,
	config.EnvSessionBuf,
	config.EnvSessionBufTotal,
	config.EnvLivenessRounds,
}

// knownEnvKeys is the full accepted key set (required ∪ optional).
var knownEnvKeys = func() map[string]bool {
	m := make(map[string]bool, len(optionalEnvKeys))
	for _, k := range optionalEnvKeys {
		m[k] = true
	}
	for _, keys := range requiredEnvKeys {
		for _, k := range keys {
			m[k] = true
		}
	}
	return m
}()

// intEnvKeys must parse as base-10 integers (folded into the Config as
// ints before validation).
var intEnvKeys = map[string]bool{
	config.EnvMetricsPort:     true,
	config.EnvRelayBuf:        true,
	config.EnvQueueBytes:      true,
	config.EnvQueueFrames:     true,
	config.EnvQueueTotal:      true,
	config.EnvOverflowMs:      true,
	config.EnvCarrierGrace:    true,
	config.EnvBootstrapWait:   true,
	config.EnvSessionBuf:      true,
	config.EnvSessionBufTotal: true,
	config.EnvLivenessRounds:  true,
}

// WriteEnvFile writes the D4 env file for role with the given KEY=VALUE
// state. Contract (design §6/§7):
//
//   - kv must contain every required key for the role and only known keys;
//   - values are validated by folding into a config.Config +
//     config.Validate(role) — on failure NOTHING is written and the
//     *config.ConfigError (or field-only error) is returned;
//   - 0600 root:root, tmp+fsync+rename (crash-safe); a previous live file
//     is backed up as <env>.bak-<unixnano> (keep-latest-3 sweep);
//   - identical rendered bytes → no write, no backup (applied=false) —
//     idempotent;
//   - applied=true, hash=sha256 of the rendered bytes on a real write.
//
// The kv VALUES never appear in any error string.
func WriteEnvFile(ctx context.Context, role Role, kv map[string]string) (applied bool, hash string, err error) {
	if err := contextCheck(ctx); err != nil {
		return false, "", err
	}
	if err := rootCheck(); err != nil {
		return false, "", err
	}
	if role != RoleGermany && role != RoleIran {
		return false, "", fmt.Errorf("%w: env file role must be %q or %q (got %q)", ErrSpec, RoleGermany, RoleIran, role)
	}
	if err := validateEnvKV(role, kv); err != nil {
		return false, "", err
	}
	desired, err := renderEnvFile(role, kv)
	if err != nil {
		return false, "", err
	}
	sum := sha256.Sum256(desired)
	h := hex.EncodeToString(sum[:])

	// The state dir is EnsureStateDir's job (0750 root:split-tunnel):
	// require it — fail fast, no side effects mid-write.
	if st, serr := os.Lstat(stateDir); serr != nil || !st.IsDir() {
		return false, "", fmt.Errorf("%w: %s must exist (run EnsureStateDir first)", ErrPreflight, stateDir)
	}
	// Refuse unsafe pre-existing objects at the live path (symlink plant).
	var oldLive []byte
	haveLive := false
	if st, lerr := os.Lstat(envPath(role)); lerr == nil {
		if !st.Mode().IsRegular() {
			return false, "", fmt.Errorf("%w: %s is a symlink or special file", ErrUnsafeTarget, envPath(role))
		}
		data, rerr := os.ReadFile(envPath(role))
		if rerr != nil {
			return false, "", fmt.Errorf("%w: cannot read existing env file: %v", ErrPreflight, rerr)
		}
		oldLive = data
		haveLive = true
	} else if !os.IsNotExist(lerr) {
		return false, "", fmt.Errorf("%w: cannot stat env file: %v", ErrPreflight, lerr)
	}
	if haveLive && string(oldLive) == string(desired) {
		// Identical state: no write, no backup, no fs disturbance.
		return false, h, nil
	}

	// Backup the previous live file (if any) — rollback artifact for T8.
	if haveLive {
		bak := envPath(role) + ".bak-" + strconv.FormatInt(nowUnixNano(), 10)
		if werr := writeFile0600(bak, oldLive); werr != nil {
			return false, "", fmt.Errorf("%w: cannot write env backup: %v", ErrPreflight, werr)
		}
		if werr := sweepManagedBackups(role, envFileMaxBackups); werr != nil {
			// Bounded housekeeping: a failed sweep must not fail an
			// otherwise-correct write, but it IS reported.
			return false, "", fmt.Errorf("%w: backup sweep: %v", ErrPreflight, werr)
		}
	}

	tmp := envPath(role) + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := writeFile0600(tmp, desired); err != nil {
		os.Remove(tmp)
		return false, "", fmt.Errorf("%w: cannot write env file: %v", ErrPreflight, err)
	}
	if err := os.Rename(tmp, envPath(role)); err != nil {
		os.Remove(tmp)
		return false, "", fmt.Errorf("%w: cannot swap env file into place: %v", ErrPreflight, err)
	}
	if err := fsyncDir(stateDir); err != nil {
		return false, "", fmt.Errorf("%w: cannot fsync state dir: %v", ErrPreflight, err)
	}
	return true, h, nil
}

// RollbackEnvFile restores the most recent env-file backup (the rollback
// partner of ApplyUnit: the env is consumed at service start, so T8 composes
// env↔unit rollback atomically — design §6). Without a backup it errors
// (there is nothing to roll back to).
func RollbackEnvFile(ctx context.Context, role Role) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := rootCheck(); err != nil {
		return err
	}
	if role != RoleGermany && role != RoleIran {
		return fmt.Errorf("%w: env file role must be %q or %q (got %q)", ErrSpec, RoleGermany, RoleIran, role)
	}
	backups, err := managedEnvBackups(role)
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		return fmt.Errorf("%w: no env-file backup exists for role %q (nothing to roll back to)", ErrPreflight, role)
	}
	latest := backups[len(backups)-1]
	data, err := os.ReadFile(latest)
	if err != nil {
		return fmt.Errorf("%w: cannot read env backup: %v", ErrPreflight, err)
	}
	tmp := envPath(role) + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := writeFile0600(tmp, data); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot stage env rollback: %v", ErrPreflight, err)
	}
	if err := os.Rename(tmp, envPath(role)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot restore env file: %v", ErrPreflight, err)
	}
	return fsyncDir(stateDir)
}

// envPath is the D4 env-file path for a role.
func envPath(role Role) string { return EnvFile(role) }

// validateEnvKV checks the kv map without touching the filesystem:
// required keys present, only known keys, values well-formed (no newlines,
// no leading '#', non-empty). Field-only errors — values never echoed.
func validateEnvKV(role Role, kv map[string]string) error {
	if len(kv) == 0 {
		return fmt.Errorf("%w: env kv map is empty", ErrSpec)
	}
	for _, k := range requiredEnvKeys[role] {
		if _, ok := kv[k]; !ok {
			return fmt.Errorf("%w: missing required key %s", ErrSpec, k)
		}
	}
	for k, v := range kv {
		if !knownEnvKeys[k] {
			return fmt.Errorf("%w: unknown env key %q", ErrSpec, k)
		}
		if v == "" {
			return fmt.Errorf("%w: key %s has an empty value (omit the key for the default)", ErrSpec, k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: key %s has a newline in its value", ErrSpec, k)
		}
		if strings.HasPrefix(v, "#") {
			return fmt.Errorf("%w: key %s value starts with a comment marker", ErrSpec, k)
		}
		if intEnvKeys[k] {
			if _, perr := strconv.ParseInt(v, 10, 64); perr != nil {
				return fmt.Errorf("%w: key %s must be an integer", ErrSpec, k)
			}
		}
	}
	// Fold into the authoritative validator. The fold uses Defaults() as
	// the base (zero-constructed Configs fail Validate: MinCarrierGraceMs).
	c := config.Defaults()
	for k, v := range kv {
		switch k {
		case config.EnvSocksListen:
			c.SocksListen = v
		case config.EnvWsListen:
			c.WsListen = v
		case config.EnvDownCarrier:
			c.DownCarrierAddr = v
		case config.EnvUpWsUrl:
			c.UpWsUrl = v
		case config.EnvDownListen:
			c.DownListen = v
		case config.EnvSecret:
			c.Secret = v
		case config.EnvAllowWeak:
			b, perr := strconv.ParseBool(v)
			if perr != nil {
				return fmt.Errorf("%w: key %s must be a boolean (true/false, 1/0)", ErrSpec, k)
			}
			c.AllowWeakSecret = b
		case config.EnvMetricsPort:
			c.MetricsPort = atoi64(v)
		case config.EnvRelayBuf:
			c.RelayBufSize = atoi64(v)
		case config.EnvQueueBytes:
			c.QueueBytesPerStream = atoi64(v)
		case config.EnvQueueFrames:
			c.QueueFramesPerStream = atoi64(v)
		case config.EnvQueueTotal:
			c.QueueBytesTotal = atoi64(v)
		case config.EnvOverflowMs:
			c.OverflowWaitMs = atoi64(v)
		case config.EnvCarrierGrace:
			c.CarrierGraceMs = atoi64(v)
		case config.EnvBootstrapWait:
			c.BootstrapWaitMs = atoi64(v)
		case config.EnvSessionBuf:
			c.SessionBufBytes = atoi64(v)
		case config.EnvSessionBufTotal:
			c.SessionBufTotal = atoi64(v)
		case config.EnvLivenessRounds:
			c.LivenessRounds = atoi64(v)
		}
	}
	if err := c.Validate(string(role)); err != nil {
		return err // *config.ConfigError — field-only by construction
	}
	return nil
}

// atoi64 is safe here: validateEnvKV already parsed the key as int64.
func atoi64(v string) int { return int(mustParseInt(v)) }

func mustParseInt(v string) int64 {
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// renderEnvFile renders the env bytes in a FIXED key order (required keys
// first in declaration order, then optional keys sorted) so equal state
// renders equal bytes.
func renderEnvFile(role Role, kv map[string]string) ([]byte, error) {
	var b strings.Builder
	for _, k := range requiredEnvKeys[role] {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(kv[k])
		b.WriteByte('\n')
	}
	var opts []string
	for k := range kv {
		if optionalEnvKeysContain(k) {
			opts = append(opts, k)
		}
	}
	sort.Strings(opts)
	for _, k := range opts {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(kv[k])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func optionalEnvKeysContain(k string) bool {
	for _, o := range optionalEnvKeys {
		if o == k {
			return true
		}
	}
	return false
}

// managedEnvBackups lists the managed backup files for a role, sorted
// ascending by their embedded unixnano timestamp (newest last). Only the
// managed prefix <env>.bak-<digits> is ever listed; foreign files are
// never touched.
func managedEnvBackups(role Role) ([]string, error) {
	// stateDir (the test-redirectable var) — MUST match the write side
	// (envPath/backup writes), or rollback/sweep would look in the wrong dir.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: cannot list state dir: %v", ErrPreflight, err)
	}
	prefix := envPath(role) + ".bak-"
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filepath.Base(prefix)) {
			continue
		}
		// A symlink planted at a managed backup name is never followed —
		// RollbackEnvFile reads these files, so a plant could redirect
		// the restore to an arbitrary path (design §8).
		if e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			continue
		}
		suffix := strings.TrimPrefix(e.Name(), filepath.Base(prefix))
		if _, perr := strconv.ParseInt(suffix, 10, 64); perr != nil {
			continue // foreign file — never touched
		}
		out = append(out, filepath.Join(stateDir, e.Name()))
	}
	sort.Strings(out) // numeric suffix: lexicographic == chronological for equal-width nanos; width is fixed by clock era
	return out, nil
}

// sweepManagedBackups keeps the newest N managed backups, removing older
// ones. Foreign files are never touched.
func sweepManagedBackups(role Role, keep int) error {
	backups, err := managedEnvBackups(role)
	if err != nil {
		return err
	}
	for _, old := range backups[:max(0, len(backups)-keep)] {
		if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// writeFile0600 writes data to path crash-safe (tmp+fsync+rename in the
// same directory, 0600 from creation) — the T3/T4 pattern.
func writeFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		f.Close()
		os.Remove(tmp)
		return firstErr(werr, serr, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return fsyncDir(dir)
}
