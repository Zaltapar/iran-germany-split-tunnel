package deploy

import (
	"path/filepath"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
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

// TestArtifactJournalRejectsDirectoriesOutsideBinaryPrefix is the RF-3
// regression: XrayDir/OriginDir are recursively removed by CleanupFresh, so a
// tampered journal must not be able to name a directory outside the managed
// binary prefix (/opt/split-tunnel).
func TestArtifactJournalRejectsDirectoriesOutsideBinaryPrefix(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	for _, tc := range []struct {
		name   string
		mutate func(*ArtifactJournal)
	}{
		{"xray /etc", func(j *ArtifactJournal) { j.XrayDir = "/etc" }},
		{"xray /opt/evil", func(j *ArtifactJournal) { j.XrayDir = "/opt/evil" }},
		{"xray prefix root", func(j *ArtifactJournal) { j.XrayDir = systemd.BinaryPrefix }},
		{"xray sibling prefix", func(j *ArtifactJournal) { j.XrayDir = systemd.BinaryPrefix + "-x/xray/v26.3.27" }},
		{"xray relative", func(j *ArtifactJournal) { j.XrayDir = "xray/v26.3.27" }},
		{"xray traversal", func(j *ArtifactJournal) { j.XrayDir = systemd.BinaryPrefix + "/xray/../../etc" }},
		{"origin /etc", func(j *ArtifactJournal) { j.OriginDir = "/etc" }},
		{"origin relative", func(j *ArtifactJournal) { j.OriginDir = "caddy/v2.8.4" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := ArtifactJournal{Role: RoleGermany}
			tc.mutate(&j)
			if err := j.validate(root); err == nil {
				t.Fatalf("out-of-prefix directory accepted: %+v", j)
			}
		})
	}
}

// TestArtifactJournalAcceptsInPrefixDirectories asserts the new containment
// check does not reject a well-formed journal whose version directories live
// inside the managed prefix (the only shape BuildJournal ever produces).
func TestArtifactJournalAcceptsInPrefixDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	j := ArtifactJournal{
		Role:      RoleIran,
		XrayDir:   systemd.BinaryPrefix + "/xray/v26.3.27",
		OriginDir: systemd.BinaryPrefix + "/caddy/v2.8.4",
	}
	if err := j.validate(root); err != nil {
		t.Fatalf("in-prefix journal rejected: %v", err)
	}
}
