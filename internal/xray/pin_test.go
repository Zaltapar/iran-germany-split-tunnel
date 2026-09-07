package xray

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestPinnedReleaseAssetsExist is the L2/CI pin-resolution test
// (architecture doc §4.2): it resolves the pinned version's release via
// the GitHub API and asserts the zip + .dgst assets exist for linux-64.
// It SKIPs (never fails) when the runner has no outbound network; a
// FAILURE means the pin points at nothing and the release must be
// re-pinned before shipping.
func TestPinnedReleaseAssetsExist(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/XTLS/Xray-core/releases/tags/"+PinnedVersion, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "split-tunnel-deploy/1.0")
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("no network for pin check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("release %s not found (status %d) — the pin points at nothing; re-pin", PinnedVersion, resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		t.Fatalf("decode release: %v", err)
	}
	zipName, _ := ZipName(ArchLinux64)
	dgstName := zipName + ".dgst"
	var haveZip, haveDgst bool
	for _, a := range rel.Assets {
		if a.Name == zipName {
			haveZip = true
		}
		if a.Name == dgstName {
			haveDgst = true
		}
	}
	if !haveZip {
		t.Errorf("release %s has no %s asset — re-pin", PinnedVersion, zipName)
	}
	if !haveDgst {
		t.Errorf("release %s has no %s asset — the §4.2 pin floor requires a .dgst; re-pin", PinnedVersion, dgstName)
	}
}
