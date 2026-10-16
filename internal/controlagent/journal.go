// journal.go — the in-flight control journal (design §5.2 F8, §5.6).
//
// A single, fixed-name JSON file inside the store root. Its presence
// is the in-flight marker for a C2 apply; its contents (the current
// state-machine state, the revision id, and the parent) drive the
// crash-recovery decision on the next agent start. It is written
// atomically (0600) before the first mutation and cleared only after
// a successful commit or a completed rollback.
//
// A journal that is malformed or whose state cannot be interpreted
// fails closed: the agent refuses every mutating op until an operator
// runs recovery.
package controlagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ControlJournalState is the closed set of state-machine states the
// journal records between apply and commit (design §5.1/§5.2).
type ControlJournalState string

const (
	JournalPrepared    ControlJournalState = "prepared"
	JournalSwapped     ControlJournalState = "swapped"
	JournalRestarted   ControlJournalState = "restarted"
	JournalVerified    ControlJournalState = "verified"
	JournalRollingBack ControlJournalState = "rolling-back"
	JournalRolledBack  ControlJournalState = "rolled-back"
)

// ControlJournalEntry is one persisted in-flight record. PreHash/NewHash
// are the sha256 of the live file before the swap and of the candidate,
// respectively; they let the crash-recovery table (design §5.6) classify
// the live file on the next start without re-running anything.
type ControlJournalEntry struct {
	ChangeID string              `json:"changeId"`
	Role     string              `json:"role"`
	State    ControlJournalState `json:"state"`
	Revision string              `json:"revision"`
	Parent   string              `json:"parent,omitempty"`
	PreHash  string              `json:"preHash,omitempty"`
	NewHash  string              `json:"newHash,omitempty"`
	// C4 two-phase handshake (c4.go / coordinated.go): XrayCand is the
	// sandbox xray candidate path reserved during PREPARE ("" when the
	// change is not xray-affected); XrayAffected records whether the
	// change owns the xray unit. Both survive a crash between prepare and
	// commit so recovery can classify the live file (design §5.6).
	XrayCand     string `json:"xrayCand,omitempty"`
	XrayAffected bool   `json:"xrayAffected,omitempty"`
}

// ControlJournal persists one in-flight control journal under a root.
type ControlJournal struct {
	Root string
}

// NewControlJournal binds a journal to a store root.
func NewControlJournal(root string) *ControlJournal {
	return &ControlJournal{Root: root}
}

func (j *ControlJournal) path() string { return filepath.Join(j.Root, "control-journal.json") }

// Write persists the entry atomically (0600, tmp+fsync+rename).
func (j *ControlJournal) Write(e ControlJournalEntry) error {
	if e.Role != "iran" && e.Role != "germany" {
		return fmt.Errorf("controlagent: journal role %q is invalid", e.Role)
	}
	if !validateStoreToken(e.Revision) {
		return fmt.Errorf("controlagent: journal revision is unsafe")
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(j.Root, 0o700); err != nil {
		return err
	}
	return atomicWriteControl(j.path(), data)
}

// Read loads the in-flight journal. os.ErrNotExist → nothing in
// flight; a malformed or tampered file → ErrManifestTampered (fail
// closed, retained for an operator to inspect).
func (j *ControlJournal) Read() (ControlJournalEntry, bool, error) {
	var e ControlJournalEntry
	data, err := os.ReadFile(j.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return e, false, nil
		}
		return e, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, false, fmt.Errorf("%w: control-journal.json is malformed", ErrManifestTampered)
	}
	switch e.State {
	case "", JournalPrepared, JournalSwapped, JournalRestarted, JournalVerified, JournalRollingBack, JournalRolledBack:
	default:
		return e, false, fmt.Errorf("%w: control-journal.json state %q", ErrManifestTampered, e.State)
	}
	return e, true, nil
}

// Clear removes the in-flight journal (idempotent).
func (j *ControlJournal) Clear() error {
	err := os.Remove(j.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// atomicWriteControl is the store's tmp+fsync+rename discipline for the
// journal file (0600, root-only).
func atomicWriteControl(path string, data []byte) error {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: journal is a symlink (refusing)", ErrStorePath)
	}
	tmp := path + ".tmp-" + fmt.Sprintf("%d", os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
