// audit_test.go — the append-only, hash-chained audit log (design
// §7.6): chain recovery across restarts, tamper detection, and the
// secret-redaction fail-closed guarantee.
package controlagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Record(AuditEntry{Actor: "operator", Concept: "splitter-policy", Outcome: "committed"}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := l.VerifyChain(); err != nil {
		t.Fatalf("fresh chain failed verification: %v", err)
	}

	// Simulate a crash+restart: a NEW log instance over the same file
	// must continue the chain (seq and prevHash), not reset it.
	l2, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Record(AuditEntry{Actor: "operator", Concept: "splitter-policy", Outcome: "committed"}); err != nil {
		t.Fatal(err)
	}
	if err := l2.VerifyChain(); err != nil {
		t.Fatalf("recovered chain failed: %v", err)
	}
	entries := l2.ReadAll()
	if len(entries) != 6 {
		t.Fatalf("expected 6 entries, got %d", len(entries))
	}
	if entries[5].Seq != 6 {
		t.Fatalf("seq did not continue: %+v", entries[5])
	}

	// Tamper with one middle line by mutating a real field (the content
	// hash covers every field except the stored hash itself, so changing
	// `actor` breaks it; the reloaded log's tip also comes from the last
	// line, so the chain still links but re-hash fails at seq 3).
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var mid AuditEntry
	if err := json.Unmarshal([]byte(lines[2]), &mid); err != nil {
		t.Fatal(err)
	}
	mid.Actor = "attacker"
	// Preserve the original key order/shape by re-marshalling; only the
	// content (and therefore the recomputed hash) changes.
	tampered, _ := json.Marshal(mid)
	lines[2] = string(tampered)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	l3, _ := NewAuditLog(path)
	if err := l3.VerifyChain(); err == nil {
		t.Fatal("tampered chain passed verification")
	}
}

func TestAuditRefusesUnredactedSecret(t *testing.T) {
	l, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	bad := AuditEntry{
		Actor: "operator", Concept: "splitter-policy", Outcome: "committed",
		Diff: []DiffEntry{{Key: "SPLIT_SECRET", Before: "hushhush", After: "shh", Redacted: false}},
	}
	if err := l.Record(bad); err == nil {
		t.Fatal("recorded an unredacted secret value")
	}
}

func TestAuditAllowsRedactedSecret(t *testing.T) {
	l, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	good := AuditEntry{
		Actor: "operator", Concept: "splitter-policy", Outcome: "committed",
		Diff: []DiffEntry{{Key: "SPLIT_SECRET", Before: fingerprint("hushhush"), After: fingerprint("shh"), Redacted: true}},
	}
	if err := l.Record(good); err != nil {
		t.Fatalf("refused a properly redacted entry: %v", err)
	}
	if err := l.VerifyChain(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditRecentLimits(t *testing.T) {
	l, _ := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	for i := 0; i < 40; i++ {
		_ = l.Record(AuditEntry{Actor: "a", Outcome: "o"})
	}
	if got := l.Recent(50); len(got) != 40 {
		t.Fatalf("Recent(50) with 40 entries: got %d", len(got))
	}
	if got := l.Recent(5); len(got) != 5 {
		t.Fatalf("Recent(5): got %d", len(got))
	}
	if got := l.Recent(5); got[len(got)-1].Seq != 40 {
		t.Fatalf("Recent(5) tail seq = %d, want 40", got[len(got)-1].Seq)
	}
}
