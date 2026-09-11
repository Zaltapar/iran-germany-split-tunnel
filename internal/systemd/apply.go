// apply.go — the transactional unit install (design §4.9). The mandated
// sequence:
//
//	preflight → desired state → candidate prep → validation → backup →
//	activation → service transition → health verification → [rollback]
//
// Failure semantics (§8): pre-swap failures change nothing; post-swap
// failures restore the known good (upgrade) or converge to "not deployed"
// (fresh install — HIGH-1). A crashed apply leaves only a
// <unit>.tmp-<pid> candidate, swept at the next preflight once the
// encoded pid is confirmed dead; a LIVE pid means another apply is in
// flight → ErrApplyInProgress (fail closed).
package systemd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// applyWaitTimeout bounds the post-apply health wait (design §4.9 step 8).
const applyWaitTimeout = 10 * time.Second

// unitBackupKeep: keep the latest N managed unit backups.
const unitBackupKeep = 3

// Result is the outcome of an ApplyUnit (design §6/§4.9 step 10). The
// deploy layer (T8) records Unit+Hash in the state file; T5 owns no state
// file (boundary documented, not duplicated).
type Result struct {
	Unit      string `json:"unit"`
	Hash      string `json:"hash"` // sha256 of the live unit bytes
	Unchanged bool   `json:"unchanged"`
	Restarted bool   `json:"restarted"`
	Health    Health `json:"health"`
	Warnings  []string
}

// ApplyUnit installs (or updates) the unit described by s, transactionally.
// It is the T8 integration contract (design §6). Root-gated; ctx-bounded;
// fail-closed at every step; two-case rollback (HIGH-1).
func ApplyUnit(ctx context.Context, m *ServiceManager, s Spec) (Result, error) {
	if m == nil {
		return Result{}, fmt.Errorf("%w: nil ServiceManager", ErrSpec)
	}
	if err := contextCheck(ctx); err != nil {
		return Result{}, err
	}
	if err := m.rootCheck(); err != nil {
		return Result{}, err
	}
	unit, err := s.unitName()
	if err != nil {
		return Result{}, err
	}
	if err := s.validate(); err != nil {
		return Result{}, err
	}
	live, err := unitPath(unit)
	if err != nil {
		return Result{}, err
	}

	// --- 1. preflight (nothing is modified yet) --------------------------
	var warnings []string
	if err := sweepCrashState(m, live); err != nil {
		return Result{}, err
	}
	if err := preflight(m, s, live); err != nil {
		return Result{}, err
	}

	// --- 2. desired state (pure render) ----------------------------------
	desired, err := RenderUnit(s)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v (step %s)", ErrSpec, err, StepRender)
	}

	// --- 3. candidate prep / idempotent no-op ----------------------------
	hadPrevious := false
	var previous []byte
	var prevState string
	if st, lerr := os.Lstat(live); lerr == nil {
		if !st.Mode().IsRegular() {
			return Result{}, fmt.Errorf("%w: %s is a symlink or special file (refusing)", ErrUnsafeTarget, live)
		}
		hadPrevious = true
		previous, err = os.ReadFile(live)
		if err != nil {
			return Result{}, fmt.Errorf("%w: cannot read live unit: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
		if string(previous) == string(desired) {
			// No-op path (design §4.9 step 3, §7 test 5): zero writes AND
			// zero executor calls — a no-op apply must never block on a
			// slow-starting unit, never mutate anything, and never query
			// systemd. Hash = sha256 of the live bytes (== desired).
			sum := sha256.Sum256(desired)
			return Result{
				Unit:      unit,
				Hash:      hex.EncodeToString(sum[:]),
				Unchanged: true,
				Restarted: false,
				Warnings:  warnings,
			}, nil
		}
		// The pre-swap state decides start-vs-restart in step 7; it is
		// fetched exactly once, and ONLY when a change is actually needed
		// (the no-op path above makes zero executor calls — §7 test 5).
		// Never re-queried after the swap: the health verification below
		// owns the post-apply state.
		prevState, err = m.State(ctx, unit)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
	} else if !os.IsNotExist(lerr) {
		return Result{}, fmt.Errorf("%w: cannot stat live unit: %v (step %s)", ErrPreflight, lerr, StepPreflight)
	}

	candidate := live + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := writeFile0644(candidate, desired); err != nil {
		os.Remove(candidate)
		return Result{}, fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepCandidate)
	}
	// From here on: every failure runs the rollback for the current phase
	// (pre-swap: remove candidate; post-swap: two-case rollback, HIGH-1).
	failPreSwap := func(step string, cause error) (Result, error) {
		rb, rbErr := rollbackPreSwap(m, candidate)
		return Result{}, applyError(unit, step, cause, rb, rbErr)
	}
	failPostSwap := func(step string, cause error) (Result, error) {
		rb, rbErr := rollbackPostSwap(m, ctx, unit, live, hadPrevious)
		return Result{}, applyError(unit, step, cause, rb, rbErr)
	}

	// --- 4. validation (systemd-analyze verify the CANDIDATE) ------------
	if out, verr := m.run(ctx, "systemd-analyze", "verify", candidate); verr != nil {
		os.Remove(candidate)
		return Result{}, fmt.Errorf("%w: %v (step %s); output: %s", ErrVerify, verr, StepVerify, excerpt(out))
	}
	// Cancellation gate (design §7-6d): a canceled ctx here is a pre-swap
	// failure — the live unit is untouched, only the candidate is removed.
	if cerr := contextCheck(ctx); cerr != nil {
		return failPreSwap(StepBackup, cerr)
	}

	// --- 5. backup (keep latest 3 managed) --------------------------------
	if hadPrevious {
		backup := live + ".bak-" + strconv.FormatInt(nowUnixNano(), 10)
		if berr := writeFile0644(backup, previous); berr != nil {
			return failPreSwap(StepBackup, berr)
		}
		if berr := sweepUnitBackups(live, unitBackupKeep); berr != nil {
			return failPreSwap(StepBackup, berr)
		}
	}

	// --- 6. activation (atomic swap, same filesystem) ---------------------
	if serr := os.Rename(candidate, live); serr != nil {
		// The rename failed: the live file is untouched (or absent on a
		// fresh install) — remove the candidate; nothing else to restore.
		os.Remove(candidate)
		return Result{}, fmt.Errorf("systemd: apply %s failed at step %s: %v; rollback: clean (live unit untouched)",
			unit, StepSwap, serr)
	}
	if serr := fsyncDir(filepath.Dir(live)); serr != nil {
		// The swap already happened; the fsync failure is durability, not
		// correctness — roll back like any post-swap failure.
		return failPostSwap(StepSwap, fmt.Errorf("dir fsync: %v", serr))
	}

	// --- 7. service transition -------------------------------------------
	if rerr := m.Reload(ctx); rerr != nil {
		return failPostSwap(StepReload, rerr)
	}
	if eerr := m.Enable(ctx, unit); eerr != nil {
		return failPostSwap(StepEnable, eerr)
	}
	// Cancellation gate: post-swap, a canceled ctx rolls back (HIGH-1).
	if cerr := contextCheck(ctx); cerr != nil {
		return failPostSwap(StepTransition, cerr)
	}
	restarted := false
	if prevState == "active" {
		if rerr := m.Restart(ctx, unit); rerr != nil {
			return failPostSwap(StepTransition, rerr)
		}
		restarted = true
	} else {
		if serr := m.Start(ctx, unit); serr != nil {
			return failPostSwap(StepTransition, serr)
		}
		restarted = true
	}

	// --- 8. health verification (exact-active semantics, HIGH-2) ---------
	// WaitActive polls is-active until EXACTLY "active" (an
	// "activating (auto-restart)" unit is never a success — §7 test 17).
	// On success the unit is known active, so Result.Health is built from
	// that fact: this makes the happy path exactly one final is-active call
	// (§7 test 4: verify → daemon-reload → enable → start → is-active×1) —
	// a separate post-wait HealthCheck would add a redundant probe.
	if cerr := contextCheck(ctx); cerr != nil {
		return failPostSwap(StepHealth, cerr)
	}
	if herr := m.WaitActive(ctx, unit, applyWaitTimeout); herr != nil {
		return failPostSwap(StepHealth, herr)
	}
	health := Health{Unit: unit, Active: true, State: "active"}

	// --- 10. state commit (Result; the state FILE is T8's) ---------------
	liveBytes, rerr := os.ReadFile(live)
	if rerr != nil {
		return Result{}, fmt.Errorf("%w: cannot read committed unit: %v", ErrPreflight, rerr)
	}
	sum := sha256.Sum256(liveBytes)
	return Result{
		Unit:      unit,
		Hash:      hex.EncodeToString(sum[:]),
		Unchanged: false,
		Restarted: restarted,
		Health:    health,
		Warnings:  warnings,
	}, nil
}

// preflight re-asserts the conditions a unit needs BEFORE any mutation
// (design §4.9 step 1): the ExecStart binary exists and is regular; the
// env file (splitters) exists, 0640-or-less, root-owned; RequiresUnits
// exist as files; per-component dir/config preconditions hold (xray: state
// + log dirs exist — created by T8's Ensure* calls, re-asserted here, NOT
// recreated mid-apply; origin: data dir + Caddyfile exist).
func preflight(m *ServiceManager, s Spec, live string) error {
	// ExecStart target must exist and be a regular file (resolving the
	// "current" pointer symlink). A unit enabled against a missing binary
	// fails at boot — refuse now.
	if st, err := os.Stat(s.BinPath); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%w: ExecStart target must exist and be a regular file (step %s)", ErrPreflight, StepPreflight)
	}
	// Splitters: the D4 env file must exist and NOT be a symlink (every
	// platform). The mode-≤-0640 and root-owned checks apply on the
	// deployment platform only: on other hosts (test fixtures) the Unix
	// permission/owner bits do not exist, so the meaningful guard there
	// is the regular-file check (design §6 Linux-gating).
	if s.Component == ComponentSplitter {
		ef := envPath(s.Role)
		st, err := os.Lstat(ef)
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%w: env file %s must exist and be a regular file (write it before apply; step %s)", ErrPreflight, ef, StepPreflight)
		}
		if runtime.GOOS == "linux" {
			if st.Mode().Perm()&^0o640 != 0 {
				return fmt.Errorf("%w: env file %s is too permissive (mode must be ≤ 0640; step %s)", ErrPreflight, ef, StepPreflight)
			}
			if !m.rootOwner(st) {
				return fmt.Errorf("%w: env file %s must be root-owned (step %s)", ErrPreflight, ef, StepPreflight)
			}
		}
	}
	// RequiresUnits: must exist as files (no dangling Wants= at boot).
	for _, u := range s.RequiresUnits {
		up, err := unitPath(u)
		if err != nil {
			return err
		}
		if st, err := os.Stat(up); err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%w: required unit %s must exist (deploy it first; step %s)", ErrPreflight, u, StepPreflight)
		}
	}
	switch s.Component {
	case ComponentXray:
		// State + log dirs must exist (EnsureStateDir/EnsureLogDir ran in
		// T8's order); re-assert, do not create mid-apply.
		if err := assertDir(stateDir); err != nil {
			return fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
		if err := assertDir(logDir); err != nil {
			return fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
		// The xray config must exist (the unit reads it at start).
		if err := assertRegular(stateDir + "/xray-germany.json"); err != nil {
			return fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
	case ComponentOrigin:
		if err := assertDir(dataDir); err != nil {
			return fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
		if err := assertRegular(stateDir + "/Caddyfile"); err != nil {
			return fmt.Errorf("%w: %v (step %s)", ErrPreflight, err, StepPreflight)
		}
	}
	return nil
}

func assertDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("%s must exist (run the Ensure* step first)", dir)
	}
	return nil
}

func assertRegular(path string) error {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s must exist and be a regular file", path)
	}
	return nil
}

// applyError formats the structured apply failure: the unit, the failed
// step, the cause, and the rollback outcome (never swallowed). The cause
// is WRAPPED, so callers can errors.Is on it (e.g. context.Canceled).
func applyError(unit, step string, cause error, rollbackOutcome string, rollbackErr error) error {
	tail := "rollback: " + rollbackOutcome
	if rollbackErr != nil {
		tail = "ROLLBACK FAILED: " + rollbackErr.Error()
	}
	return fmt.Errorf("%w: apply %s failed at step %s; %s", cause, unit, step, tail)
}

// rollbackPreSwap recovers a failure BEFORE the atomic swap: the live unit
// (if any) is byte-identical to what it was; only the candidate may need
// removing. Returns the outcome string or an ErrRollback error.
func rollbackPreSwap(m *ServiceManager, candidate string) (string, error) {
	if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: remove-candidate: %v (manual intervention required)", ErrRollback, err)
	}
	return "clean (live unit untouched)", nil
}

// rollbackPostSwap implements the two-case recovery (HIGH-1) for failures
// AFTER the atomic swap:
//
//   - hadPrevious=true (upgrade): restore the newest managed backup over
//     the live path (atomic backup→tmp→rename), daemon-reload, restart
//     best-effort → "restored known good (+restart outcome)";
//   - hadPrevious=false (fresh install): the new unit must NOT stay
//     enabled on a broken binary (it would crash-loop at every boot) —
//     remove the unit file + disable + daemon-reload → "removed (not
//     deployed)".
//
// Best-effort sub-steps append their errors (never swallowed silently,
// never masking the primary failure); a rollback that cannot complete
// returns ErrRollback demanding manual intervention.
func rollbackPostSwap(m *ServiceManager, ctx context.Context, unit, live string, hadPrevious bool) (string, error) {
	var steps []string
	add := func(format string, args ...any) { steps = append(steps, fmt.Sprintf(format, args...)) }

	if hadPrevious {
		backups, berr := managedUnitBackups(live)
		if berr != nil {
			add("list-backups: %v", berr)
		} else if len(backups) == 0 {
			add("list-backups: none found")
		} else {
			latest := backups[len(backups)-1]
			tmp := live + ".tmp-rollback-" + strconv.Itoa(os.Getpid())
			data, rerr := os.ReadFile(latest)
			if rerr != nil {
				add("read-backup: %v", rerr)
			} else if werr := writeFile0644(tmp, data); werr != nil {
				os.Remove(tmp)
				add("stage-backup: %v", werr)
			} else if serr := os.Rename(tmp, live); serr != nil {
				os.Remove(tmp)
				add("restore-swap: %v", serr)
			} else {
				add("restore-swap: ok")
			}
		}
		if rerr := m.Reload(ctx); rerr != nil {
			add("daemon-reload: %v", rerr)
		} else {
			add("daemon-reload: ok")
		}
		// Best-effort: restore service state to the previous known good.
		if rerr := m.Restart(ctx, unit); rerr != nil {
			add("restart(best-effort): %v", rerr)
		} else {
			add("restart(best-effort): ok")
		}
		return "restored known good; " + strings.Join(steps, "; "), nil
	}

	// Fresh install: converge to "not deployed".
	if err := os.Remove(live); err != nil && !os.IsNotExist(err) {
		add("remove-unit: %v", err)
	} else {
		add("remove-unit: ok")
	}
	if err := m.Disable(ctx, unit); err != nil {
		add("disable: %v", err)
	} else {
		add("disable: ok")
	}
	if err := m.Reload(ctx); err != nil {
		add("daemon-reload: %v", err)
	} else {
		add("daemon-reload: ok")
	}
	// A failed fresh install must not leave the wants symlink behind.
	// (systemctl disable usually removes it; this is the belt-and-braces
	// pass for the case where disable itself failed above.)
	if err := os.Remove(filepath.Join(wantsDir, unit)); err != nil && !os.IsNotExist(err) {
		add("remove-wants-symlink: %v", err)
	} else {
		add("remove-wants-symlink: ok")
	}
	return "removed (not deployed); " + strings.Join(steps, "; "), nil
}

// sweepCrashState removes a leftover <live>.tmp-<pid> candidate whose
// encoded pid is DEAD; a live pid means another apply is in flight
// (ErrApplyInProgress — fail closed). Foreign files are never touched.
func sweepCrashState(m *ServiceManager, live string) error {
	base := filepath.Base(live)
	entries, err := os.ReadDir(filepath.Dir(live))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: cannot list unit dir: %v", ErrPreflight, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		suffix, ok := strings.CutPrefix(e.Name(), base+".tmp-")
		if !ok {
			continue // foreign file — never touched
		}
		pid, perr := strconv.Atoi(suffix)
		if perr != nil {
			continue // foreign file — never touched
		}
		if m.PidAlive(pid) {
			return fmt.Errorf("%w: %s.tmp-%d encodes a live pid", ErrApplyInProgress, base, pid)
		}
		if err := os.Remove(filepath.Join(filepath.Dir(live), e.Name())); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w: cannot remove crashed candidate: %v", ErrPreflight, err)
		}
	}
	return nil
}

// managedUnitBackups lists <live>.bak-<digits> files sorted ascending by
// their embedded timestamp (newest last). Foreign files never touched.
func managedUnitBackups(live string) ([]string, error) {
	dir := filepath.Dir(live)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	prefix := filepath.Base(live) + ".bak-"
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// A symlink (or any non-regular object) planted at a managed
		// backup name is never followed — the rollback restore reads
		// these files, so a plant could redirect the restore (design §8).
		if e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			continue
		}
		suffix, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok {
			continue
		}
		if _, perr := strconv.ParseInt(suffix, 10, 64); perr != nil {
			continue // foreign file
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sortStrings(out)
	return out, nil
}

// sweepUnitBackups keeps the newest N managed unit backups.
func sweepUnitBackups(live string, keep int) error {
	backups, err := managedUnitBackups(live)
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

// writeFile0644 writes a unit (or backup) file crash-safe: tmp + fsync +
// rename, 0644 from creation (unit files carry no secret — D4 — so 0644
// root:root is correct; staging runs the same mode).
func writeFile0644(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
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

// sortStrings is a tiny dependency-free sort (backups lists are tiny).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
