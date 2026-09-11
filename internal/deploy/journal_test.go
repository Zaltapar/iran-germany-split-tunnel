package deploy

import (
	"path/filepath"
	"testing"
)

func TestArtifactJournalValidatesOwnedArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	j := ArtifactJournal{
		Role:     RoleGermany,
		Files:    []string{filepath.Join(root, "xray-germany.json")},
		Units:    []string{"xray-germany.service", "germany-splitter.service"},
		XrayDir:  "/opt/split-tunnel/xray/v26.3.27",
		Firewall: true,
	}
	if err := j.validate(root); err != nil {
		t.Fatalf("valid journal: %v", err)
	}
}

func TestArtifactJournalRejectsTraversalAndUnsafeUnits(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	for _, journal := range []ArtifactJournal{
		{Role: RoleIran, Files: []string{filepath.Join(filepath.Dir(root), "escape")}},
		{Role: RoleIran, Units: []string{"../evil.service"}},
		{Role: "other"},
	} {
		if err := journal.validate(root); err == nil {
			t.Fatalf("unsafe journal accepted: %+v", journal)
		}
	}
}
