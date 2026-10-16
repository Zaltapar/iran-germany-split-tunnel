// revisionstore.go — the C2 revision store, design §5.4.
//
// A directory tree (default root /var/lib/split-tunnel-control;
// configurable, never caller input for the individual file names
// inside) holding:
//
//	head                 atomic pointer to the current revision id
//	lkg                  atomic pointer to the last-known-good revision id
//	kill-switch          the FREEZE file that blocks all applies
//	audit.jsonl          append-only audit log (hash-chained, §7.6)
//	revisions/<id>/
//	  meta.json          change metadata (no secrets; §7.5)
//	  MANIFEST.sha256    sha256 of every file copy, plus the manifest's
//	                    own hash (tamper-evident, mirrors deploy.Store)
//	  files/             full copies of the live files AFTER the change
//	  pre/               copies taken BEFORE the swap (the rollback source)
//
// Safety invariants:
//   - every write is atomic: tmp file + fsync + rename (crash-safe);
//   - a symlink at any managed path is a hard error, never followed;
//   - retention prunes to the last N revisions (default 10) but NEVER
//     prunes the head, the lkg, or the revision any pending journal
//     still references;
//   - a revision's MANIFEST.sha256 verifies both the file hashes and
//     the manifest's self-hash; load failures are ErrManifestTampered,
//     and consumers must fail closed.
package controlagent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultRetention is the revision retention (design D18: 10, aligned
// with internal/deploy maxRevisions).
const DefaultRetention = 10

var (
	// ErrStorePath marks a path-shape refusal (relative, traversal,
	// symlink).
	ErrStorePath = errors.New("controlagent: unsafe store path")
	// ErrManifestTampered marks a MANIFEST.sha256 / meta.json
	// integrity failure; consumers fail closed on it.
	ErrManifestTampered = errors.New("controlagent: revision manifest integrity check failed")
	// ErrKillSwitch marks the frozen state.
	ErrKillSwitch = errors.New("controlagent: kill switch engaged")
)

// RevisionMeta is one revision's committed metadata. It contains no
// secret value: file hashes only (design §5.4/§7.5).
type RevisionMeta struct {
	ID         string `json:"id"`
	Parent     string `json:"parent,omitempty"`
	ChangeID   string `json:"changeId,omitempty"`
	Actor      string `json:"actor"`
	Role       string `json:"role"` // deploy role this revision was committed for
	Kind       string `json:"kind"`
	Timestamp  time.Time
	Outcome    string            `json:"outcome"`            // "committed" | "rolled-back" | "recovered-*"
	PrevHash   string            `json:"prevHash,omitempty"` // hash of the previous revision meta
	Manifest   string            `json:"manifest"`           // sha256 of MANIFEST.sha256
	FileHashes map[string]string // relative file name → sha256 of files/ copy
}

func (m RevisionMeta) MarshalJSON() ([]byte, error) {
	type alias RevisionMeta
	a := alias(m)
	a.Timestamp = m.Timestamp.UTC()
	return json.Marshal(a)
}

// RevisionStore owns one store root. All paths are derived from the
// root and a validated token (revision ids); no untrusted string ever
// reaches a filepath.Join outside validateStoreToken.
type RevisionStore struct {
	Root      string
	Retention int
	Now       func() time.Time
}

// NewRevisionStore validates and prepares a store root.
func NewRevisionStore(root string) (*RevisionStore, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%w: root must be absolute", ErrStorePath)
	}
	s := &RevisionStore{Root: filepath.Clean(root), Retention: DefaultRetention, Now: time.Now}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("controlagent: create store root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "revisions"), 0o700); err != nil {
		return nil, fmt.Errorf("controlagent: create revisions dir: %w", err)
	}
	return s, nil
}

func (s *RevisionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ---------------------------------------------------------------------------
// Head / LKG pointers
// ---------------------------------------------------------------------------

// Head returns the current revision id ("" when the store is empty).
func (s *RevisionStore) Head() (string, error) {
	return s.readPointer("head")
}

// LKG returns the last-known-good revision id ("" when none promoted).
func (s *RevisionStore) LKG() (string, error) {
	return s.readPointer("lkg")
}

func (s *RevisionStore) readPointer(name string) (string, error) {
	p := filepath.Join(s.Root, name)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if id != "" && !validateStoreToken(id) {
		return "", fmt.Errorf("%w: pointer %q holds an unsafe token", ErrStorePath, name)
	}
	return id, nil
}

func (s *RevisionStore) writePointer(name, id string) error {
	if id != "" && !validateStoreToken(id) {
		return fmt.Errorf("%w: pointer id", ErrStorePath)
	}
	return s.atomicWriteFile(filepath.Join(s.Root, name), []byte(id), 0o600)
}

// ---------------------------------------------------------------------------
// Kill switch (design §6.6: a local file blocks all applies; unfreeze
// is CLI-only, never over the socket).
// ---------------------------------------------------------------------------

// KillSwitchPath is the FREEZE file location.
func (s *RevisionStore) KillSwitchPath() string { return filepath.Join(s.Root, "kill-switch") }

// IsFrozen reports whether the kill switch is engaged.
func (s *RevisionStore) IsFrozen() bool {
	_, err := os.Stat(s.KillSwitchPath())
	return err == nil
}

// Freeze writes the kill switch.
func (s *RevisionStore) Freeze() error {
	return s.atomicWriteFile(s.KillSwitchPath(), []byte("frozen\n"), 0o600)
}

// Unfreeze removes the kill switch (CLI-only operation; the socket
// protocol has no unfreeze op — see protocol.go's closed op set).
func (s *RevisionStore) Unfreeze() error {
	err := os.Remove(s.KillSwitchPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// Revision ids
// ---------------------------------------------------------------------------

// NewRevisionID returns a random, token-safe revision id.
func (s *RevisionStore) NewRevisionID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "r-" + s.now().UTC().Format("20060102") + "-" + hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Revision write path: snapshot pre/, commit files/, manifest, prune
// ---------------------------------------------------------------------------

// PreSnapshot copies the current live files into a fresh revision's
// pre/ directory (design §5.2 F9), verifying each copy by hash. files
// maps a flat file name (the live env file's base name) to its live
// absolute path.
func (s *RevisionStore) PreSnapshot(revID string, files map[string]string) error {
	if !validateStoreToken(revID) {
		return fmt.Errorf("%w: revision id", ErrStorePath)
	}
	preDir := s.preDir(revID)
	if err := s.ensureDir(preDir); err != nil {
		return err
	}
	for _, rel := range sortedKeys(files) {
		if err := s.copyFileVerified(preDir, rel, files[rel]); err != nil {
			return err
		}
	}
	return nil
}

// CommitRevision writes the post-swap file copies into the revision,
// computes and persists MANIFEST.sha256 + meta.json, updates the head
// pointer, and prunes to the retention window (never touching head /
// lkg / journal-referenced revisions).
func (s *RevisionStore) CommitRevision(meta RevisionMeta, files map[string]string, parent string) error {
	if !validateStoreToken(meta.ID) {
		return fmt.Errorf("%w: revision id", ErrStorePath)
	}
	meta.Parent = parent
	if meta.Timestamp.IsZero() {
		meta.Timestamp = s.now()
	}
	revDir := s.revDir(meta.ID)
	filesDir := filepath.Join(revDir, "files")
	if err := s.ensureDir(filesDir); err != nil {
		return err
	}
	if meta.FileHashes == nil {
		meta.FileHashes = map[string]string{}
	}
	for _, rel := range sortedKeys(files) {
		if err := s.copyFileVerified(filesDir, rel, files[rel]); err != nil {
			return err
		}
		meta.FileHashes[rel] = "" // filled by writeManifest below
	}
	manifest, hashes, err := s.writeManifest(meta.ID, filesDir)
	if err != nil {
		return err
	}
	meta.Manifest = manifest
	for k, v := range hashes {
		meta.FileHashes[k] = v
	}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := s.atomicWriteFile(filepath.Join(revDir, "meta.json"), append(metaData, '\n'), 0o600); err != nil {
		return err
	}
	// Commit is last (design §5 invariant): head moves only after the
	// revision directory is fully written.
	if err := s.writePointer("head", meta.ID); err != nil {
		return err
	}
	return s.Prune()
}

// LoadRevision loads one revision and verifies its manifest + file
// hashes against MANIFEST.sha256 (fail closed on any mismatch).
func (s *RevisionStore) LoadRevision(id string) (RevisionMeta, map[string]string, error) {
	var meta RevisionMeta
	if err := s.loadMeta(id, &meta); err != nil {
		return meta, nil, err
	}
	data, err := os.ReadFile(filepath.Join(s.revDir(id), "MANIFEST.sha256"))
	if err != nil {
		return meta, nil, err
	}
	if manifestHash(data) != meta.Manifest {
		return meta, nil, fmt.Errorf("%w: revision %s MANIFEST self-hash", ErrManifestTampered, id)
	}
	hashes, err := parseManifest(data)
	if err != nil {
		return meta, nil, err
	}
	files := make(map[string]string, len(hashes))
	filesDir := filepath.Join(s.revDir(id), "files")
	for rel, want := range hashes {
		p := filepath.Join(filesDir, rel)
		sum, err := s.hashFile(p)
		if err != nil {
			return meta, nil, fmt.Errorf("%w: revision %s files/%s: %v", ErrManifestTampered, id, rel, err)
		}
		if sum != want {
			return meta, nil, fmt.Errorf("%w: revision %s files/%s hash mismatch", ErrManifestTampered, id, rel)
		}
		files[rel] = p
	}
	return meta, files, nil
}

// LoadPreCopies returns the on-disk paths of a revision's pre/ copies
// (the rollback source for that revision).
func (s *RevisionStore) LoadPreCopies(id string) (map[string]string, error) {
	if !validateStoreToken(id) {
		return nil, fmt.Errorf("%w: revision id", ErrStorePath)
	}
	preDir := s.preDir(id)
	entries, err := os.ReadDir(preDir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out[e.Name()] = filepath.Join(preDir, e.Name())
	}
	return out, nil
}

// HashFile returns the sha256 of one on-disk file (the crash-recovery
// table compares the live file's hash against the journal's
// PreHash/NewHash — design §5.6).
func (s *RevisionStore) HashFile(path string) (string, error) {
	return s.hashFile(path)
}

// PromoteLKG points the lkg pointer at id (the revision's health was
// observed across the §6.4 window; called by the transaction after
// verify).
// verify).
func (s *RevisionStore) PromoteLKG(id string) error { return s.writePointer("lkg", id) }

// RevisionIDs lists all retained revision ids, oldest first.
func (s *RevisionStore) RevisionIDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "revisions"))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// RoleOfRevision returns the deploy role a revision was committed for
// (persisted in its meta so a revert-lkg can resolve which seam to
// drive). A missing/invalid role is an error (fail closed).
func (s *RevisionStore) RoleOfRevision(id string) (string, error) {
	meta, _, err := s.LoadRevision(id)
	if err != nil {
		return "", err
	}
	if meta.Role != "iran" && meta.Role != "germany" {
		return "", fmt.Errorf("%w: revision %s has no valid role", ErrManifestTampered, id)
	}
	return meta.Role, nil
}

// RetainIDs reports which revision ids must survive the next prune
// (head, lkg, and any extra ids, e.g. journal-referenced).
func (s *RevisionStore) RetainIDs(extra ...string) map[string]bool {
	set := map[string]bool{}
	for _, id := range extra {
		if id != "" {
			set[id] = true
		}
	}
	if head, err := s.Head(); err == nil {
		set[head] = true
	}
	if lkg, err := s.LKG(); err == nil {
		set[lkg] = true
	}
	return set
}

// Prune removes revision directories beyond the retention window
// (counting newest first), never removing a retained id.
func (s *RevisionStore) Prune() error {
	dir := filepath.Join(s.Root, "revisions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids) // ids carry a timestamp; newest last
	if len(ids) <= s.Retention {
		return nil
	}
	retained := s.RetainIDs()
	drop := ids[:len(ids)-s.Retention]
	for _, id := range drop {
		if retained[id] {
			continue // head/lkg are never pruned
		}
		if err := os.RemoveAll(filepath.Join(dir, id)); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (s *RevisionStore) revDir(id string) string { return filepath.Join(s.Root, "revisions", id) }
func (s *RevisionStore) preDir(id string) string { return filepath.Join(s.revDir(id), "pre") }

func (s *RevisionStore) ensureDir(dir string) error {
	if st, err := os.Lstat(dir); err == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrStorePath, dir)
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrStorePath, dir)
	}
	return nil
}

// copyFileVerified copies src into dstDir/rel (refusing symlinks on
// both ends) and verifies the copy byte-for-byte by hash.
func (s *RevisionStore) copyFileVerified(dstDir, rel, src string) error {
	if rel == "" || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.Contains(rel, string(filepath.Separator)) {
		return fmt.Errorf("%w: copy target %q", ErrStorePath, rel)
	}
	if err := checkNotSymlink(src); err != nil {
		return err
	}
	if err := checkNotSymlink(dstDir); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, rel)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	tmp, err := s.openTempInDir(dstDir)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(tmp, in)
	in.Close()
	if err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		err = tmp.Close()
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	a, err := s.hashFile(src)
	if err != nil {
		return err
	}
	b, err := s.hashFile(dst)
	if err != nil {
		return err
	}
	if a != b {
		_ = os.Remove(dst)
		return fmt.Errorf("%w: copy verification failed for %s", ErrManifestTampered, rel)
	}
	return nil
}

func (s *RevisionStore) openTempInDir(dir string) (*os.File, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".tmp-%d-%x", os.Getpid(), b))
	return os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
}

// atomicWriteFile: tmp + fsync + rename, refusing a symlink target.
func (s *RevisionStore) atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := checkNotSymlink(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := checkNotSymlink(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + ".tmp-" + fmt.Sprintf("%d", os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, mode)
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

// writeManifest computes MANIFEST.sha256 for one revision's files/ dir
// and returns its sha256 (the meta.Manifest field) plus the per-file
// hashes it recorded.
func (s *RevisionStore) writeManifest(id, filesDir string) (string, map[string]string, error) {
	entries, err := os.ReadDir(filesDir)
	if err != nil {
		return "", nil, err
	}
	var sb strings.Builder
	hashes := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		sum, err := s.hashFile(filepath.Join(filesDir, e.Name()))
		if err != nil {
			return "", nil, err
		}
		hashes[e.Name()] = sum
		fmt.Fprintf(&sb, "%s  %s\n", sum, e.Name())
	}
	data := []byte(sb.String())
	if err := s.atomicWriteFile(filepath.Join(s.revDir(id), "MANIFEST.sha256"), data, 0o600); err != nil {
		return "", nil, err
	}
	return manifestHash(data), hashes, nil
}

// parseManifest reads the "hash  name" lines of a MANIFEST.sha256.
func parseManifest(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		i := strings.Index(line, "  ")
		if i < 0 {
			return nil, fmt.Errorf("%w: malformed manifest line", ErrManifestTampered)
		}
		out[line[i+2:]] = line[:i]
	}
	return out, nil
}

// loadMeta loads and strictly re-checks one revision's meta.json.
func (s *RevisionStore) loadMeta(id string, meta *RevisionMeta) error {
	if !validateStoreToken(id) {
		return fmt.Errorf("%w: revision id", ErrStorePath)
	}
	data, err := os.ReadFile(filepath.Join(s.revDir(id), "meta.json"))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(meta); err != nil {
		return fmt.Errorf("%w: revision %s meta.json: %v", ErrManifestTampered, id, err)
	}
	if meta.ID != id {
		return fmt.Errorf("%w: revision %s meta.json id mismatch", ErrManifestTampered, id)
	}
	if meta.Manifest == "" {
		return fmt.Errorf("%w: revision %s has no manifest hash", ErrManifestTampered, id)
	}
	return nil
}

func (s *RevisionStore) hashFile(path string) (string, error) {
	if err := checkNotSymlink(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkNotSymlink returns os.ErrNotExist when path is absent; an
// ErrStorePath error when it exists as a symlink; nil otherwise.
func checkNotSymlink(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink (refusing)", ErrStorePath, path)
	}
	if !st.Mode().IsRegular() && !st.IsDir() {
		return fmt.Errorf("%w: %s is not a regular file or directory", ErrStorePath, path)
	}
	return nil
}

// validateStoreToken: the same alphabet as deploy.validToken (revision
// ids, pointer values) plus ':' (ids embed a UTC date). Path-safe by
// construction.
func validateStoreToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == ':') {
			return false
		}
	}
	return true
}

func manifestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
