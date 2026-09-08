package origin

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// PinnedVersion is the Caddy release this deploy line is built against
// (design §2.1: a single pinned constant, bumped deliberately per
// project release — never "latest"). Chosen as v2.11.4, whose release
// ships the upstream-published caddy_<v>_checksums.txt (SHA-512) and
// whose WS-forwarding + timeout semantics were verified against the
// pinned source tag (design §1, D7).
const PinnedVersion = "v2.11.4"

const caddyReleaseBaseURL = "https://github.com/caddyserver/caddy/releases/download/"

// CaddyArch is a Caddy release-asset architecture suffix.
// NOTE: deliberately a SEPARATE enum from xray.Arch (D3): Caddy
// publishes NO linux-386 asset and different suffixes (amd64, not
// "linux-64").
type CaddyArch string

// Supported Caddy release assets (name suffixes of caddy_<v>_linux_<arch>.tar.gz).
const (
	CaddyArchLinuxAMD64   CaddyArch = "amd64"
	CaddyArchLinuxARM64   CaddyArch = "arm64"
	CaddyArchLinuxARM5    CaddyArch = "armv5"
	CaddyArchLinuxARM6    CaddyArch = "armv6"
	CaddyArchLinuxARM7    CaddyArch = "armv7"
	CaddyArchLinuxPPC64LE CaddyArch = "ppc64le"
	CaddyArchLinuxRISCV64 CaddyArch = "riscv64"
	CaddyArchLinuxS390X   CaddyArch = "s390x"
)

var caddyVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// ValidVersion reports whether v is a well-formed Caddy release tag
// (vMAJOR.MINOR.PATCH).
func ValidVersion(v string) bool { return caddyVersionRe.MatchString(v) }

// ArchForGOARCH maps a runtime.GOARCH to the matching release asset.
// Only Linux targets are managed; 386 is NOT published upstream, so it
// is an explicit error (unlike xray, which ships linux-32).
func ArchForGOARCH(goarch string) (CaddyArch, error) {
	switch goarch {
	case "amd64":
		return CaddyArchLinuxAMD64, nil
	case "arm64":
		return CaddyArchLinuxARM64, nil
	case "arm":
		// Go's "arm" covers v5..v7; v7 is the floor for a modern
		// userland (same mapping xray uses for linux-arm32-v7a).
		return CaddyArchLinuxARM7, nil
	case "386":
		return "", fmt.Errorf("origin: caddy does not publish a linux-386 asset (amd64/arm64/arm only)")
	default:
		return "", fmt.Errorf("origin: unsupported architecture %q (linux amd64/arm64/arm only)", goarch)
	}
}

// DefaultArch returns the asset for the current machine.
func DefaultArch() (CaddyArch, error) { return ArchForGOARCH(runtime.GOARCH) }

// assetVersion is the version string as it appears in Caddy's release
// ASSET file names: Caddy strips the leading "v" in asset names
// (caddy_2.11.4_linux_amd64.tar.gz) while the release TAG in the URL
// keeps it (/releases/download/v2.11.4/...). Verified against the live
// v2.11.4 release asset list.
func assetVersion(version string) string { return strings.TrimPrefix(version, "v") }

// TarName is the release asset file name for a version + arch
// (caddy_<v>_linux_<arch>.tar.gz; the asset name drops the "v").
func TarName(version string, arch CaddyArch) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("origin: invalid version %q", version)
	}
	if !knownCaddyArch(arch) {
		return "", fmt.Errorf("origin: unsupported arch %q", arch)
	}
	return "caddy_" + assetVersion(version) + "_linux_" + string(arch) + ".tar.gz", nil
}

// TarURL is the direct download URL of the pinned (or given) release tar.gz.
func TarURL(version string, arch CaddyArch) (string, error) {
	n, err := TarName(version, arch)
	if err != nil {
		return "", err
	}
	return caddyReleaseBaseURL + version + "/" + n, nil
}

// ChecksumName is the upstream-published checksums file name
// (caddy_<v>_checksums.txt; the asset name drops the "v").
func ChecksumName(version string) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("origin: invalid version %q", version)
	}
	return "caddy_" + assetVersion(version) + "_checksums.txt", nil
}

// ChecksumURL is the download URL of the upstream checksums file
// (SHA-512 lines, "gpg --print-md SHA512" two-space format).
func ChecksumURL(version string) (string, error) {
	n, err := ChecksumName(version)
	if err != nil {
		return "", err
	}
	return caddyReleaseBaseURL + version + "/" + n, nil
}

// VersionDir joins a prefix with a version (the versioned layout:
// <prefix>/caddy/<version>/caddy). Rollback = keep the old dir.
func VersionDir(prefix, version string) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("origin: invalid version %q", version)
	}
	p := strings.TrimRight(prefix, "/")
	if p == "" {
		return "", fmt.Errorf("origin: empty prefix")
	}
	return p + "/caddy/" + version, nil
}

func knownCaddyArch(a CaddyArch) bool {
	switch a {
	case CaddyArchLinuxAMD64, CaddyArchLinuxARM64, CaddyArchLinuxARM5,
		CaddyArchLinuxARM6, CaddyArchLinuxARM7, CaddyArchLinuxPPC64LE,
		CaddyArchLinuxRISCV64, CaddyArchLinuxS390X:
		return true
	}
	return false
}
