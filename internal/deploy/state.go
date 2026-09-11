package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrTampered        = errors.New("deploy: manifest integrity check failed")
	ErrInvalidManifest = errors.New("deploy: invalid manifest")
	ErrUnsafePath      = errors.New("deploy: unsafe state path")
)

const maxRevisions = 10

// Store persists deployment state below Root. Production uses
// /etc/split-tunnel; tests provide a temporary root.
type Store struct {
	Root string
	Now  func() time.Time
}

func NewStore(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%w: root must be absolute", ErrUnsafePath)
	}
	return &Store{Root: filepath.Clean(root)}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) manifestPath() string { return filepath.Join(s.Root, "state.json") }
func (s *Store) revisionsDir() string { return filepath.Join(s.Root, "revisions") }

func (s *Store) Load() (Manifest, error) {
	data, err := os.ReadFile(s.manifestPath())
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: state.json is malformed: %v", ErrTampered, err)
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	actual, err := manifestHash(m)
	if err != nil {
		return Manifest{}, err
	}
	if !strings.EqualFold(actual, m.ManifestHash) {
		return Manifest{}, fmt.Errorf("%w: state.json", ErrTampered)
	}
	return m, nil
}

func (s *Store) Save(m Manifest) error {
	if err := validateManifest(m); err != nil {
		return err
	}
	hash, err := manifestHash(m)
	if err != nil {
		return err
	}
	m.ManifestHash = hash
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := s.ensureRoot(); err != nil {
		return err
	}
	return atomicWrite(s.manifestPath(), data, 0o600)
}

// Commit writes a new revision snapshot and then the manifest. Old revisions
// are pruned only after the new manifest is safely installed.
func (s *Store) Commit(m Manifest, label string) (Manifest, error) {
	now := s.now()
	if m.Schema == 0 {
		m.Schema = SchemaVersion
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	if m.Generation == "" {
		m.Generation = fmt.Sprintf("s-%d", now.UnixNano())
	}
	if m.Paths.StateRoot == "" {
		m.Paths.StateRoot = s.Root
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	if err := s.ensureRoot(); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(s.revisionsDir(), 0o700); err != nil {
		return Manifest{}, fmt.Errorf("deploy: create revisions: %w", err)
	}
	id := fmt.Sprintf("%s-%d", m.Generation, now.UnixNano())
	m.Revisions = append([]Revision(nil), m.Revisions...)
	m.Revisions = append(m.Revisions, Revision{ID: id, Timestamp: now, Label: label, Snapshot: filepath.Join("revisions", id+".json")})
	if len(m.Revisions) > maxRevisions {
		m.Revisions = m.Revisions[len(m.Revisions)-maxRevisions:]
	}
	for i := range m.Revisions {
		m.Revisions[i].Snapshot = filepath.Join("revisions", m.Revisions[i].ID+".json")
	}
	latest := m.Revisions[len(m.Revisions)-1]
	snapshot := filepath.Join(s.Root, filepath.FromSlash(latest.Snapshot))
	data, err := canonicalManifestBytes(m)
	if err != nil {
		return Manifest{}, err
	}
	if err := atomicWrite(snapshot, data, 0o600); err != nil {
		return Manifest{}, err
	}
	if err := s.Save(m); err != nil {
		return Manifest{}, err
	}
	if err := s.prune(m.Revisions); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (s *Store) ReadRevision(id string) (Manifest, error) {
	if !validToken(id) {
		return Manifest{}, fmt.Errorf("%w: revision id", ErrUnsafePath)
	}
	data, err := os.ReadFile(filepath.Join(s.revisionsDir(), id+".json"))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: revision: %v", ErrInvalidManifest, err)
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (s *Store) ensureRoot() error {
	if st, err := os.Lstat(s.Root); err == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: root", ErrUnsafePath)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(s.Root, 0o700); err != nil {
			return fmt.Errorf("deploy: create state root: %w", err)
		}
	} else {
		return err
	}
	return os.Chmod(s.Root, 0o700)
}

func (s *Store) prune(revisions []Revision) error {
	keep := make(map[string]bool, len(revisions))
	for _, r := range revisions {
		keep[r.ID] = true
	}
	entries, err := os.ReadDir(s.revisionsDir())
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || keep[strings.TrimSuffix(name, ".json")] {
			continue
		}
		if err := os.Remove(filepath.Join(s.revisionsDir(), name)); err != nil {
			return err
		}
	}
	return nil
}

func validateManifest(m Manifest) error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("%w: schema %d", ErrInvalidManifest, m.Schema)
	}
	if m.Role != RoleIran && m.Role != RoleGermany {
		return fmt.Errorf("%w: role", ErrInvalidManifest)
	}
	if m.Paths.StateRoot == "" || !filepath.IsAbs(m.Paths.StateRoot) {
		return fmt.Errorf("%w: stateRoot", ErrInvalidManifest)
	}
	return nil
}

func manifestHash(m Manifest) (string, error) {
	m.ManifestHash = ""
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalManifestBytes(m Manifest) ([]byte, error) {
	hash, err := manifestHash(m)
	if err != nil {
		return nil, err
	}
	m.ManifestHash = hash
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("deploy: create parent: %w", err)
	}
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink target", ErrUnsafePath)
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("deploy: create temp: %w", err)
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
		return fmt.Errorf("deploy: atomic rename: %w", err)
	}
	_ = os.Chmod(path, mode)
	ok = true
	return nil
}

func validToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
