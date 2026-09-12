package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// ArtifactJournal records the ownership-scoped pre-state and scope of one
// transaction. It is persisted separately from the committed manifest while a
// mutation is in flight: its PRESENCE is the in-flight marker (a stale
// journal after a crash means the host may be inconsistent), and its contents
// tell an operator exactly which units/files the transaction intended to
// own and which pre-existed. It is removed only after a successful commit.
//
// Units is the complete unit set of the desired state; PreUnits are the
// units the previous manifest already deployed (restore distinguishes
// "created by this transaction → remove" from "upgraded → restore backup").
// PreFiles are the config files that existed before the transaction (newly
// created files are deletable on recovery; pre-existing ones are left for
// their owner's rollback path). XrayDir/OriginDir are the canonical
// project-owned version directories: outside the state root but always
// contained within the managed binary prefix (validate enforces this, and
// CleanupFresh's removal is prefix-bounded and symlink-safe).
type ArtifactJournal struct {
	Generation string   `json:"generation"`
	Role       string   `json:"role"`
	Files      []string `json:"files,omitempty"`
	PreFiles   []string `json:"preFiles,omitempty"`
	Units      []string `json:"units,omitempty"`
	PreUnits   []string `json:"preUnits,omitempty"`
	Firewall   bool     `json:"firewall"`
	XrayDir    string   `json:"xrayDir,omitempty"`
	OriginDir  string   `json:"originDir,omitempty"`
}

func (j ArtifactJournal) validate(root string) error {
	if j.Role != RoleIran && j.Role != RoleGermany {
		return fmt.Errorf("deploy: journal role is invalid")
	}
	for _, path := range append(append([]string{}, j.Files...), j.PreFiles...) {
		if !filepath.IsAbs(path) || !within(root, path) {
			return fmt.Errorf("deploy: journal file is outside state root")
		}
	}
	for _, unit := range append(append([]string{}, j.Units...), j.PreUnits...) {
		if unit == "" || filepath.Base(unit) != unit || filepath.Ext(unit) != ".service" {
			return fmt.Errorf("deploy: journal unit is invalid")
		}
	}
	// XrayDir/OriginDir are the persisted version directories CleanupFresh
	// recursively removes, so they are containment-checked against the
	// managed binary prefix (RF-3): a tampered journal must not be able to
	// point a recursive delete outside /opt/split-tunnel.
	for _, dir := range []string{j.XrayDir, j.OriginDir} {
		if dir == "" {
			continue
		}
		if !binaryPrefixContained(dir) {
			return fmt.Errorf("deploy: journal directory is outside binary prefix")
		}
	}
	return nil
}

// binaryPrefixContained reports whether dir is an absolute, rooted path
// strictly inside systemd.BinaryPrefix. Rootedness is checked textually (a
// leading "/") because filepath.IsAbs is false for "/opt/..." on non-Unix
// hosts, while the managed paths are always Unix-absolute by construction.
func binaryPrefixContained(dir string) bool {
	return strings.HasPrefix(dir, "/") && within(systemd.BinaryPrefix, dir)
}

// journalPath is the single in-flight journal location under the state root.
// It is a fixed, project-owned file name — never caller input.
func journalPath(root string) string { return filepath.Join(root, "journal.json") }

// WriteJournal persists the in-flight journal atomically (0600). The journal
// is written BEFORE any mutation runs and is the evidence for recovery; its
// contents are ownership-scoped and secret-free by construction.
func (s *Store) WriteJournal(j ArtifactJournal) error {
	if err := j.validate(s.Root); err != nil {
		return err
	}
	data, err := marshalJournal(j)
	if err != nil {
		return err
	}
	if err := s.ensureRoot(); err != nil {
		return err
	}
	return atomicWrite(journalPath(s.Root), data, 0o600)
}

// ReadJournal loads and re-validates the in-flight journal. A missing journal
// is os.ErrNotExist (nothing in flight); a malformed or out-of-root journal
// is ErrTampered — recovery must fail closed on both.
func (s *Store) ReadJournal() (ArtifactJournal, error) {
	data, err := os.ReadFile(journalPath(s.Root))
	if err != nil {
		return ArtifactJournal{}, err
	}
	var j ArtifactJournal
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return ArtifactJournal{}, fmt.Errorf("%w: journal.json is malformed", ErrTampered)
	}
	if err := j.validate(s.Root); err != nil {
		return ArtifactJournal{}, fmt.Errorf("%w: journal.json: %v", ErrTampered, err)
	}
	return j, nil
}

// ClearJournal removes the in-flight journal after a successful commit. A
// missing journal is not an error (idempotent clear).
func (s *Store) ClearJournal() error {
	err := os.Remove(journalPath(s.Root))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deploy: remove journal: %w", err)
	}
	return nil
}

func marshalJournal(j ArtifactJournal) ([]byte, error) {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
