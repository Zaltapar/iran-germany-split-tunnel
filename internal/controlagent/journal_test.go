// journal_test.go — the in-flight control journal (design §5.2 F8,
// §5.6): atomic write, strict read, tamper → fail closed, idempotent
// clear.
package controlagent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalAbsentIsNotInFlight(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	e, inFlight, err := j.Read()
	if err != nil {
		t.Fatalf("absent journal error: %v", err)
	}
	if inFlight {
		t.Fatal("absent journal reports in-flight")
	}
	_ = e
}

func TestJournalWriteReadRoundTrip(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	in := ControlJournalEntry{
		ChangeID: "c-1", Role: "iran", State: JournalSwapped,
		Revision: "r-1", Parent: "r-0", PreHash: "p", NewHash: "n",
	}
	if err := j.Write(in); err != nil {
		t.Fatal(err)
	}
	got, inFlight, err := j.Read()
	if err != nil || !inFlight {
		t.Fatalf("read back: inFlight=%v err=%v", inFlight, err)
	}
	if got != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestJournalRejectsInvalidRole(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	if err := j.Write(ControlJournalEntry{Role: "xray", State: JournalPrepared, Revision: "r-1"}); err == nil {
		t.Fatal("accepted invalid role")
	}
}

func TestJournalMalformedFailsClosed(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	if err := os.WriteFile(j.path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Read(); !errors.Is(err, ErrManifestTampered) {
		t.Fatalf("expected tamper error, got %v", err)
	}
}

func TestJournalUnknownStateFailsClosed(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	if err := os.WriteFile(j.path(), []byte(`{"changeId":"c","role":"iran","state":"bogus","revision":"r-1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Read(); !errors.Is(err, ErrManifestTampered) {
		t.Fatalf("expected tamper error, got %v", err)
	}
}

func TestJournalUnknownFieldFailsClosed(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	if err := os.WriteFile(j.path(), []byte(`{"changeId":"c","role":"iran","state":"prepared","revision":"r-1","extra":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Read(); !errors.Is(err, ErrManifestTampered) {
		t.Fatalf("expected tamper error, got %v", err)
	}
}

func TestJournalClearIdempotent(t *testing.T) {
	j := NewControlJournal(t.TempDir())
	_ = j.Write(ControlJournalEntry{Role: "germany", State: JournalPrepared, Revision: "r-9"})
	if err := j.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := j.Clear(); err != nil {
		t.Fatalf("second clear should be idempotent: %v", err)
	}
	if _, inFlight, _ := j.Read(); inFlight {
		t.Fatal("still in-flight after clear")
	}
}

func TestJournalSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	j := NewControlJournal(root)
	p := j.path()
	if err := os.Symlink(filepath.Join(root, "elsewhere"), p); err != nil {
		t.Skipf("cannot create symlink on this host: %v", err)
	}
	if err := j.Write(ControlJournalEntry{Role: "iran", State: JournalPrepared, Revision: "r-1"}); err == nil {
		t.Fatal("write through a symlinked journal file was accepted")
	}
}
