package origin

import "testing"

func TestPinnedVersionShape(t *testing.T) {
	if !ValidVersion(PinnedVersion) {
		t.Errorf("PinnedVersion %q does not match vM.m.p", PinnedVersion)
	}
}

func TestValidVersion(t *testing.T) {
	for _, good := range []string{"v2.11.4", "v1.0.0", "v26.3.27"} {
		if !ValidVersion(good) {
			t.Errorf("ValidVersion(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", "latest", "v2.11", "v2.11.4-beta.1", "2.11.4", "v2.11.4 "} {
		if ValidVersion(bad) {
			t.Errorf("ValidVersion(%q) = true, want false", bad)
		}
	}
}

func TestTarNamesAndURLs(t *testing.T) {
	// The asset NAME drops the leading "v" (caddy_2.11.4_...), but the
	// release TAG in the URL keeps it (/releases/download/v2.11.4/...).
	name, err := TarName(PinnedVersion, CaddyArchLinuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	wantName := "caddy_2.11.4_linux_amd64.tar.gz"
	if name != wantName {
		t.Errorf("TarName = %q, want %q", name, wantName)
	}
	url, err := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://github.com/caddyserver/caddy/releases/download/" + PinnedVersion + "/" + wantName
	if url != wantURL {
		t.Errorf("TarURL = %q, want %q", url, wantURL)
	}
	ck, err := ChecksumURL(PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	wantCK := "https://github.com/caddyserver/caddy/releases/download/" + PinnedVersion + "/caddy_2.11.4_checksums.txt"
	if ck != wantCK {
		t.Errorf("ChecksumURL = %q, want %q", ck, wantCK)
	}
	// Unknown arch + bad version rejected.
	if _, err := TarName(PinnedVersion, CaddyArch("linux-64")); err == nil {
		t.Error("unknown arch accepted")
	}
	if _, err := TarURL("latest", CaddyArchLinuxAMD64); err == nil {
		t.Error("invalid version accepted")
	}
}

func TestArchForGOARCH(t *testing.T) {
	cases := map[string]CaddyArch{"amd64": CaddyArchLinuxAMD64, "arm64": CaddyArchLinuxARM64, "arm": CaddyArchLinuxARM7}
	for goarch, want := range cases {
		got, err := ArchForGOARCH(goarch)
		if err != nil || got != want {
			t.Errorf("ArchForGOARCH(%s) = %v, %v; want %v", goarch, got, err, want)
		}
	}
	// Caddy publishes NO linux-386 asset (D3): explicit error.
	if _, err := ArchForGOARCH("386"); err == nil {
		t.Error("386 accepted (caddy has no linux-386 asset)")
	}
	if _, err := ArchForGOARCH("s390x"); err == nil {
		t.Error("s390x GOARCH accepted (not a managed linux target)")
	}
}

func TestVersionDir(t *testing.T) {
	dir, err := VersionDir("/opt/split-tunnel", PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/opt/split-tunnel/caddy/" + PinnedVersion; dir != want {
		t.Errorf("VersionDir = %q, want %q", dir, want)
	}
	if _, err := VersionDir("", PinnedVersion); err == nil {
		t.Error("empty prefix accepted")
	}
	if _, err := VersionDir("/opt/split-tunnel", "latest"); err == nil {
		t.Error("invalid version accepted")
	}
}
