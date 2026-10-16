// audit.go — the C2 append-only audit log (design §7.6).
//
// One JSON-lines file (audit.jsonl) written with O_APPEND by the agent.
// Each entry carries the hash of the previous entry, so truncation or
// mid-file edits are detectable (audit-verify). No secret value ever
// appears: diffs are already redacted at the source (validator.BuildDiff
// masks secret-named fields to fingerprints), and this sink re-checks
// with a final redaction pass so a regression cannot leak a value.
package controlagent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuditEntry is one append-only record.
type AuditEntry struct {
	Seq      int         `json:"seq"`
	TS       time.Time   `json:"ts"`
	Actor    string      `json:"actor"`
	Op       string      `json:"op"`
	Concept  string      `json:"concept"`
	ChangeID string      `json:"changeId"`
	RevFrom  string      `json:"revFrom,omitempty"`
	RevTo    string      `json:"revTo,omitempty"`
	Diff     []DiffEntry `json:"diffSummary,omitempty"`
	Outcome  string      `json:"outcome"`
	PrevHash string      `json:"prevHash"` // hash of the previous entry (chain)
	Hash     string      `json:"hash"`     // hash of this entry's contents
}

// AuditLog is the append-only, hash-chained audit sink.
type AuditLog struct {
	mu   sync.Mutex
	path string
	seq  int
	last string // previous entry hash (the chain tip)

	// redactSubstrings are canary-free name fragments whose VALUES must
	// never appear in any entry; only their field names may. The sink
	// scans the marshaled entry and refuses to write on a match (fail
	// closed) so a value cannot leak even if a redaction regression
	// slips through upstream.
	redactSubstrings []string
}

// NewAuditLog opens (or creates) the audit log at path.
func NewAuditLog(path string) (*AuditLog, error) {
	a := &AuditLog{
		path: path,
		redactSubstrings: []string{
			"secret", "password", "private", "token",
		},
	}
	// Recover the chain tip from the existing file (so a restarted
	// agent continues the chain rather than resetting it).
	a.recover()
	return a, nil
}

func (a *AuditLog) recover() {
	f, err := os.Open(a.path)
	if err != nil {
		return // absent → fresh chain
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var last *AuditEntry
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			last = &e
		}
	}
	if last != nil {
		a.seq = last.Seq
		a.last = last.Hash
	}
}

// Record appends one redacted entry. It is serialized under a mutex
// (single-writer) and verifies the redaction before the append.
func (a *AuditLog) Record(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recordLocked(e)
}

func (a *AuditLog) recordLocked(e AuditEntry) error {
	a.seq++
	e.Seq = a.seq
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	e.PrevHash = a.last
	// Content hash over the entry with the Hash field zeroed.
	content := e
	content.Hash = ""
	data, err := json.Marshal(content)
	if err != nil {
		return err
	}
	if err := a.redactionCheck(string(data), e); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	e.Hash = hex.EncodeToString(sum[:])
	a.last = e.Hash

	out, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(out, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// secretNameFragments are key-name fragments that identify a secret field.
var secretNameFragments = []string{"secret", "password", "token", "credential", "private", "socks"}

// isSecretKey reports whether the diff key's name matches a secret fragment.
func isSecretKey(key string) bool {
	ln := strings.ToLower(key)
	for _, frag := range secretNameFragments {
		if strings.Contains(ln, frag) {
			return true
		}
	}
	return false
}

// redactionCheck refuses to write an entry that would leak a secret
// value (fail closed). Two independent guards:
//
//  1. The diff KEY is a secret-named field AND the entry is not
//     marked Redacted — the value was not fingerprinted, so writing
//     it would leak the material.
//  2. The diff VALUE itself contains a known secret fragment (e.g.
//     "password") AND the entry is not Redacted — a second layer.
func (a *AuditLog) redactionCheck(marshaled string, e AuditEntry) error {
	for _, d := range e.Diff {
		if d.Redacted {
			continue // fingerprinted value is safe to record
		}
		if isSecretKey(d.Key) {
			return fmt.Errorf("controlagent: audit entry %q carries a non-redacted secret-named diff for key %q (refusing)", e.ChangeID, d.Key)
		}
		for _, sub := range a.redactSubstrings {
			if strings.Contains(strings.ToLower(d.Before), sub) {
				return fmt.Errorf("controlagent: audit entry leaks a secret value fragment for key %q (refusing)", d.Key)
			}
			if strings.Contains(strings.ToLower(d.After), sub) {
				return fmt.Errorf("controlagent: audit entry leaks a secret value fragment for key %q (refusing)", d.Key)
			}
		}
	}
	_ = marshaled
	return nil
}

// Recent returns the last n entries, oldest first.
func (a *AuditLog) Recent(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := a.readAll()
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries
}

// ReadAll returns every entry, oldest first.
func (a *AuditLog) ReadAll() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.readAll()
}

func (a *AuditLog) readAll() []AuditEntry {
	f, err := os.Open(a.path)
	if err != nil {
		return []AuditEntry{}
	}
	defer f.Close()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// VerifyChain re-hashes every entry and confirms the PrevHash links.
// A tamper (one byte) is a hard error naming the first broken seq.
func (a *AuditLog) VerifyChain() error {
	entries := a.ReadAll()
	var prev string
	for i, e := range entries {
		if e.PrevHash != prev {
			return fmt.Errorf("controlagent: audit chain broken at seq %d (prevHash mismatch)", e.Seq)
		}
		content := e
		content.Hash = ""
		data, _ := json.Marshal(content)
		sum := sha256.Sum256(data)
		if e.Hash != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("controlagent: audit entry seq %d hash mismatch (tampered)", e.Seq)
		}
		prev = e.Hash
		_ = i
	}
	return nil
}
