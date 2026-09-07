// Package xray is the managed-transport adapter for Xray-core
// (architecture doc §4): it performs the same steps the official
// XTLS/Xray-install script uses — pinned release zip + upstream .dgst
// SHA-256 verification, extraction into a project-owned versioned prefix,
// `xray version` smoke check, `xray run -test` gate — but with this
// project's own pin, verification and manifest semantics. It does NOT
// reimplement any Xray functionality; everything runtime goes through
// the pinned binary via an Executor.
package xray

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// PinnedVersion is the Xray-core release this deploy line is built
// against (architecture doc §4.2: a single pinned constant, bumped
// deliberately per project release — never "latest"). Chosen as the
// newest stable release whose zip ships a .dgst sidecar and the
// `x2025 reality keypair` subcommand (verified against the GitHub
// release at implementation time; true of all recent stable releases).
const PinnedVersion = "v26.3.27"

const releaseBaseURL = "https://github.com/XTLS/Xray-core/releases/download/"

// Arch is a release-asset architecture suffix.
type Arch string

// Supported release assets (name suffixes of Xray-linux-<arch>.zip).
const (
	ArchLinux64    Arch = "linux-64"
	ArchLinuxARM64 Arch = "linux-arm64-v8a"
	ArchLinuxARM7  Arch = "linux-arm32-v7a"
	ArchLinux32    Arch = "linux-32"
)

var versionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// ValidVersion reports whether v is a well-formed Xray release tag
// (vMAJOR.MINOR.PATCH). The pin and every operator-supplied override
// must pass this before any network or filesystem action.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// ArchForGOARCH maps a runtime.GOARCH to the matching release asset.
// Only Linux targets are managed by this package (the deploy roles run
// on Linux); anything else is an explicit error.
func ArchForGOARCH(goarch string) (Arch, error) {
	switch goarch {
	case "amd64":
		return ArchLinux64, nil
	case "arm64":
		return ArchLinuxARM64, nil
	case "arm":
		return ArchLinuxARM7, nil
	case "386":
		return ArchLinux32, nil
	default:
		return "", fmt.Errorf("xray: unsupported architecture %q (linux amd64/arm64/arm/386 only)", goarch)
	}
}

// DefaultArch returns the asset for the current machine.
func DefaultArch() (Arch, error) { return ArchForGOARCH(runtime.GOARCH) }

// ZipName is the release asset file name for an arch.
func ZipName(arch Arch) (string, error) {
	if !knownArch(arch) {
		return "", fmt.Errorf("xray: unsupported arch %q", arch)
	}
	return "Xray-" + string(arch) + ".zip", nil
}

// ZipURL is the direct download URL of the pinned (or given) release zip.
func ZipURL(version string, arch Arch) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("xray: invalid version %q", version)
	}
	n, err := ZipName(arch)
	if err != nil {
		return "", err
	}
	return releaseBaseURL + version + "/" + n, nil
}

// DigestURL is the .dgst sidecar URL (upstream-published checksums).
func DigestURL(version string, arch Arch) (string, error) {
	u, err := ZipURL(version, arch)
	if err != nil {
		return "", err
	}
	return u + ".dgst", nil
}

// VersionDir joins a prefix with a version (the versioned layout:
// <prefix>/v26.3.27/xray). A rollback is a pointer swap between these
// directories — old versions stay on disk until cleanup.
func VersionDir(prefix, version string) (string, error) {
	if !ValidVersion(version) {
		return "", fmt.Errorf("xray: invalid version %q", version)
	}
	p := strings.TrimRight(prefix, "/")
	if p == "" {
		return "", fmt.Errorf("xray: empty prefix")
	}
	return p + "/" + version, nil
}

func knownArch(a Arch) bool {
	switch a {
	case ArchLinux64, ArchLinuxARM64, ArchLinuxARM7, ArchLinux32:
		return true
	}
	return false
}
