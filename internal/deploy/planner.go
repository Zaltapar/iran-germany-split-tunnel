package deploy

import (
	"fmt"
	"reflect"
	"strconv"
)

// PlanDesired compares the current manifest with desired state without any
// filesystem, process, service, or firewall side effects.
//
// # Empty/unknown rule
//
// Structural fields (versions, paths, modes, firewall backend, pairing state)
// are compared strictly. Convergence-identity fields (binary hashes, the
// rendered-unit hashes, the origin render fingerprint and its parameters, the
// Reality public fingerprint, and pairing fingerprints) follow the
// documented rule: an EMPTY desired value means "this request does not assert
// the field" and is NOT compared, so a legacy on-disk manifest that never
// recorded the field (or a request that genuinely carries no artifact hash)
// plans as unchanged. A NON-EMPTY desired value that differs from the recorded
// value is genuine drift and is planned; the following apply records it, so the
// next plan is Unchanged.
func PlanDesired(current *Manifest, desired DesiredState) (Plan, error) {
	if desired.Role != RoleIran && desired.Role != RoleGermany {
		return Plan{}, fmt.Errorf("%w: desired role", ErrInvalidManifest)
	}
	if current != nil && current.Role != desired.Role {
		return Plan{}, fmt.Errorf("%w: role cannot change in place", ErrInvalidManifest)
	}
	var changes []Change
	if current == nil {
		changes = append(changes, Change{Field: "install", After: desired.Role})
	} else {
		compare := func(field, before, after string, destructive bool) {
			if before != after {
				changes = append(changes, Change{Field: field, Before: before, After: after, Destructive: destructive})
			}
		}
		// compareIdentity applies the empty/unknown rule: an empty desired
		// value is unasserted and never plans drift.
		compareIdentity := func(field, before, after string, destructive bool) {
			if after == "" {
				return
			}
			compare(field, before, after, destructive)
		}

		// Structural: versions and paths.
		compare("components.splitter.version", current.Components.Splitter.Version, desired.Components.Splitter.Version, false)
		compare("components.splitter.path", current.Components.Splitter.Path, desired.Components.Splitter.Path, true)
		compare("components.xray.version", current.Components.Xray.Version, desired.Components.Xray.Version, false)
		compare("components.xray.path", current.Components.Xray.Path, desired.Components.Xray.Path, true)

		// Identity: binary content hashes (true hashes for both components).
		compareIdentity("components.splitter.sha256", current.Components.Splitter.SHA256, desired.Components.Splitter.SHA256, true)
		compareIdentity("components.xray.sha256", current.Components.Xray.SHA256, desired.Components.Xray.SHA256, true)
		// Identity: the xray-only PUBLIC Reality parameter fingerprint.
		compareIdentity("components.xray.realityFingerprint", current.Components.Xray.RealityFingerprint, desired.Components.Xray.RealityFingerprint, true)

		// Origin: structural mode/version/domain plus the identity fields the
		// origin renderer actually consumes.
		compare("components.origin.mode", current.Components.Origin.Mode, desired.Components.Origin.Mode, true)
		compare("components.origin.version", current.Components.Origin.Version, desired.Components.Origin.Version, false)
		compare("components.origin.domain", current.Components.Origin.Domain, desired.Components.Origin.Domain, true)
		compareIdentity("components.origin.upstreamAddr", current.Components.Origin.UpstreamAddr, desired.Components.Origin.UpstreamAddr, true)
		compareIdentity("components.origin.originPort", strconv.Itoa(current.Components.Origin.OriginPort), strconv.Itoa(desired.Components.Origin.OriginPort), true)
		compareIdentity("components.origin.acmeChallenge", current.Components.Origin.ACMEChallenge, desired.Components.Origin.ACMEChallenge, true)
		compareIdentity("components.origin.acmeEmail", current.Components.Origin.ACMEEmail, desired.Components.Origin.ACMEEmail, true)
		compareIdentity("components.origin.cdnSecurity", current.Components.Origin.CDNSecurity, desired.Components.Origin.CDNSecurity, true)
		compareIdentity("components.origin.cdnOriginTrust", current.Components.Origin.CDNOriginTrust, desired.Components.Origin.CDNOriginTrust, true)
		compareIdentity("components.origin.caddyfileHash", current.Components.Origin.CaddyfileHash, desired.Components.Origin.CaddyfileHash, true)

		// Managed paths (structural when recorded; the fixed systemd-derived
		// locations are identity so a moved managed path is visible).
		compare("paths.env", current.Paths.Env, desired.Paths.Env, true)
		compare("paths.config", current.Paths.Config, desired.Paths.Config, true)
		compareIdentity("paths.unitDir", current.Paths.UnitDir, desired.Paths.UnitDir, true)
		compareIdentity("paths.wantsDir", current.Paths.WantsDir, desired.Paths.WantsDir, true)
		compareIdentity("paths.logDir", current.Paths.LogDir, desired.Paths.LogDir, true)
		compareIdentity("paths.dataDir", current.Paths.DataDir, desired.Paths.DataDir, true)
		compareIdentity("paths.binaryPrefix", current.Paths.BinaryPrefix, desired.Paths.BinaryPrefix, true)
		compareIdentity("paths.unitsBackupDir", current.Paths.UnitsBackupDir, desired.Paths.UnitsBackupDir, true)
		compareIdentity("paths.binaryPointer", current.Paths.BinaryPointer, desired.Paths.BinaryPointer, true)
		if len(desired.Paths.UnitFiles) > 0 && !reflect.DeepEqual(current.Paths.UnitFiles, desired.Paths.UnitFiles) {
			changes = append(changes, Change{Field: "paths.unitFiles", Before: strconv.Itoa(len(current.Paths.UnitFiles)), After: strconv.Itoa(len(desired.Paths.UnitFiles)), Destructive: true})
		}

		// Firewall.
		compare("firewall.backend", current.Firewall.Backend, desired.Firewall.Backend, true)
		compare("firewall.ownership", current.Firewall.Ownership, desired.Firewall.Ownership, true)
		compare("firewall.rulesHash", current.Firewall.RulesHash, desired.Firewall.RulesHash, true)

		// Pairing: state is structural; fingerprints are identity (and are
		// carried forward by the controller, so a re-apply stays a no-op).
		compare("pairing.state", current.Pairing.State, desired.Pairing.State, true)
		if len(desired.Pairing.Fingerprints) > 0 && !reflect.DeepEqual(current.Pairing.Fingerprints, desired.Pairing.Fingerprints) {
			changes = append(changes, Change{Field: "pairing.fingerprints", Before: strconv.Itoa(len(current.Pairing.Fingerprints)), After: strconv.Itoa(len(desired.Pairing.Fingerprints)), Destructive: true})
		}

		// Services: unit identity and the rendered-unit hash. The hash is
		// identity (unasserted when empty); unit/component are structural.
		if !servicesEqual(current.Services, desired.Services) {
			changes = append(changes, Change{Field: "services", Before: strconv.Itoa(len(current.Services)), After: strconv.Itoa(len(desired.Services)), Destructive: true})
		}
	}
	return Plan{Changes: changes, Unchanged: len(changes) == 0}, nil
}

// servicesEqual compares two service lists. Unit and Component are structural;
// Hash follows the empty/unknown rule (an empty desired hash is unasserted).
// Length must always match.
func servicesEqual(current, desired []ServiceState) bool {
	if len(current) != len(desired) {
		return false
	}
	for i := range desired {
		if current[i].Unit != desired[i].Unit || current[i].Component != desired[i].Component {
			return false
		}
		if desired[i].Hash != "" && current[i].Hash != desired[i].Hash {
			return false
		}
	}
	return true
}
