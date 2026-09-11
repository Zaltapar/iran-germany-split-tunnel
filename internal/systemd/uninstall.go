// uninstall.go — uninstall support for T8 (design §4.11/§6).
//
// Boundary (documented, not duplicated): these functions manage UNIT FILES
// ONLY. Binaries, env files, state, and logs are owned by the deploy layer
// and are NEVER removed here.
package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DisableUnit stops the unit (when active/transitioning) and disables it.
// Sequence per design §4.11: stop (if active) → disable → remove the wants
// symlink (belt-and-braces: systemctl disable usually removes it; the
// direct removal covers the case where disable itself failed).
func DisableUnit(ctx context.Context, m *ServiceManager, s Spec) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := m.rootCheck(); err != nil {
		return err
	}
	unit, err := s.unitName()
	if err != nil {
		return err
	}
	state, err := m.State(ctx, unit)
	if err != nil {
		return err
	}
	if state == "active" || state == "activating" || state == "deactivating" {
		if err := m.Stop(ctx, unit); err != nil {
			return err
		}
	}
	if err := m.Disable(ctx, unit); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(wantsDir, unit)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: cannot remove wants symlink for %s: %v", ErrPreflight, unit, err)
	}
	return nil
}

// RollbackLast restores the newest managed unit backup for s's unit over the
// live path (atomic: backup→tmp→rename + dir fsync), then daemon-reload and
// restart. Operator-initiated (unlike ApplyUnit's post-swap rollback, where
// restart is best-effort): a failing reload/restart IS reported, with the
// outcome explicit (the unit file is already restored when either fails).
func RollbackLast(ctx context.Context, m *ServiceManager, s Spec) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := m.rootCheck(); err != nil {
		return err
	}
	unit, err := s.unitName()
	if err != nil {
		return err
	}
	live, err := unitPath(unit)
	if err != nil {
		return err
	}
	backups, err := managedUnitBackups(live)
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		return fmt.Errorf("%w: no unit backup exists for %s (nothing to roll back to)", ErrPreflight, unit)
	}
	latest := backups[len(backups)-1]
	data, err := os.ReadFile(latest)
	if err != nil {
		return fmt.Errorf("%w: cannot read unit backup: %v", ErrPreflight, err)
	}
	tmp := live + ".tmp-rollback-" + strconv.Itoa(os.Getpid())
	if err := writeFile0644(tmp, data); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot stage unit rollback: %v", ErrPreflight, err)
	}
	if err := os.Rename(tmp, live); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w: cannot restore unit: %v", ErrPreflight, err)
	}
	if err := fsyncDir(filepath.Dir(live)); err != nil {
		return fmt.Errorf("%w: cannot fsync unit dir: %v", ErrPreflight, err)
	}
	if err := m.Reload(ctx); err != nil {
		return fmt.Errorf("%w: unit file restored but daemon-reload failed: %v", ErrPreflight, err)
	}
	if err := m.Restart(ctx, unit); err != nil {
		return fmt.Errorf("%w: unit file restored but restart failed: %v", ErrPreflight, err)
	}
	return nil
}

// RemoveUnit removes the unit file entirely (design §4.11): DisableUnit +
// back up the unit file to <UnitsBackupDir>/<unit>.<unixnano> (keep-latest-3
// sweep, managed entries only) + remove the live file + daemon-reload.
// NEVER removes binaries, env files, state, or logs (the deploy layer owns
// those — documented boundary).
func RemoveUnit(ctx context.Context, m *ServiceManager, s Spec) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := m.rootCheck(); err != nil {
		return err
	}
	unit, err := s.unitName()
	if err != nil {
		return err
	}
	if err := DisableUnit(ctx, m, s); err != nil {
		return err
	}
	live, err := unitPath(unit)
	if err != nil {
		return err
	}
	if st, lerr := os.Lstat(live); lerr == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is a symlink or special file (refusing)", ErrUnsafeTarget, live)
		}
		if err := os.MkdirAll(unitsBackupDir, 0o750); err != nil {
			return fmt.Errorf("%w: cannot create unit backup dir: %v", ErrPreflight, err)
		}
		data, rerr := os.ReadFile(live)
		if rerr != nil {
			return fmt.Errorf("%w: cannot read unit for backup: %v", ErrPreflight, err)
		}
		backup := filepath.Join(unitsBackupDir, unit+"."+strconv.FormatInt(nowUnixNano(), 10))
		if werr := writeFile0644(backup, data); werr != nil {
			return fmt.Errorf("%w: cannot write unit backup: %v", ErrPreflight, werr)
		}
		if err := sweepUnitsBackups(unit, unitBackupKeep); err != nil {
			return err
		}
		if err := os.Remove(live); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w: cannot remove unit: %v", ErrPreflight, err)
		}
	} else if !os.IsNotExist(lerr) {
		return fmt.Errorf("%w: cannot stat unit: %v", ErrPreflight, lerr)
	}
	return m.Reload(ctx)
}

// managedUnitsBackups lists <UnitsBackupDir>/<unit>.<digits> files sorted
// ascending by their embedded timestamp (newest last). Managed entries only;
// foreign files are never touched.
func managedUnitsBackups(unit string) ([]string, error) {
	entries, err := os.ReadDir(unitsBackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	prefix := unit + "."
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// A symlink planted at a managed backup name is never followed
		// (design §8).
		if e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			continue
		}
		suffix, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok {
			continue
		}
		if _, perr := strconv.ParseInt(suffix, 10, 64); perr != nil {
			continue // foreign file — never touched
		}
		out = append(out, filepath.Join(unitsBackupDir, e.Name()))
	}
	sortStrings(out)
	return out, nil
}

// sweepUnitsBackups keeps the newest N managed RemoveUnit backups for a unit.
func sweepUnitsBackups(unit string, keep int) error {
	backups, err := managedUnitsBackups(unit)
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
