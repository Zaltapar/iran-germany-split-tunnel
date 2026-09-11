package deploy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// ArtifactJournal records only project-owned artifacts touched by one
// transaction. It is persisted separately from the committed manifest while a
// mutation is in flight and is the sole input to fresh cleanup/upgrade restore.
type ArtifactJournal struct {
	Generation string   `json:"generation"`
	Role       string   `json:"role"`
	Files      []string `json:"files,omitempty"`
	Units      []string `json:"units,omitempty"`
	Firewall   bool     `json:"firewall"`
	XrayDir    string   `json:"xrayDir,omitempty"`
	OriginDir  string   `json:"originDir,omitempty"`
}

func (j ArtifactJournal) validate(root string) error {
	if j.Role != RoleIran && j.Role != RoleGermany {
		return fmt.Errorf("deploy: journal role is invalid")
	}
	for _, path := range j.Files {
		if !filepath.IsAbs(path) || !within(root, path) {
			return fmt.Errorf("deploy: journal file is outside state root")
		}
	}
	for _, unit := range j.Units {
		if unit == "" || filepath.Base(unit) != unit || filepath.Ext(unit) != ".service" {
			return fmt.Errorf("deploy: journal unit is invalid")
		}
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
