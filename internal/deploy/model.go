// Package deploy owns deployment desired-state planning and persistent state.
// It is deliberately above the transport engine and below cmd/splitterctl.
//
// # Convergence identity and unknown values
//
// The persisted Manifest records the identity of what was deployed so a later
// plan can detect genuine drift. Identity fields (binary content hashes,
// rendered unit hashes, the origin render fingerprint, the Reality public
// fingerprint, pairing fingerprints, and the managed-path constants) may be
// ABSENT on one side:
//
//   - A manifest written by an older schema, or a request that genuinely does
//     not carry an artifact hash, records an empty value.
//   - An empty DESIRED value means "this request does not assert this field",
//     so the planner does NOT compare it and never fabricates one. This is the
//     documented rule that lets an old on-disk manifest load without spurious
//     destructive drift.
//   - A NON-EMPTY desired value that differs from the recorded value (including
//     a recorded empty value) is genuine drift and is planned ONCE; the
//     subsequent apply records the value, so the following plan is Unchanged.
//
// Structural fields (versions, paths, modes, firewall backend, pairing state)
// keep strict equality semantics and are always compared.
package deploy

import "time"

// SchemaVersion is the current persisted Manifest schema. Schema 1 is the
// legacy shape; it predates the convergence-identity fields below. Schema 2
// adds those fields additively. Old schema-1 files still load: every added
// field is `omitempty`, so a legacy file re-marshals to byte-identical JSON and
// its stored ManifestHash still validates. A legacy manifest is upgraded to the
// current schema the next time it is committed.
const SchemaVersion = 2

// legacySchema reports whether v is an accepted on-disk schema that predates
// the current one. Only schema 1 is recognised; any other value is rejected by
// validateManifest so a tampered or unknown schema fails closed.
func legacySchema(v int) bool { return v == 1 }

const (
	RoleIran    = "iran"
	RoleGermany = "germany"
)

type Manifest struct {
	Schema       int            `json:"schema"`
	Role         string         `json:"role"`
	Generation   string         `json:"generation"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	ManifestHash string         `json:"manifestHash"`
	Components   Components     `json:"components"`
	Paths        Paths          `json:"paths"`
	Pairing      PairingState   `json:"pairing"`
	Services     []ServiceState `json:"services,omitempty"`
	Firewall     FirewallState  `json:"firewall"`
	Revisions    []Revision     `json:"revisions,omitempty"`
}

type Components struct {
	Splitter ComponentState `json:"splitter"`
	Xray     ComponentState `json:"xray,omitempty"`
	Origin   OriginState    `json:"origin,omitempty"`
}

// ComponentState is the recorded identity of one managed binary. SHA256 is a
// TRUE binary content hash for every component. The xray component additionally
// carries RealityFingerprint, a fingerprint of the PUBLIC Reality parameters
// (SNI+shortId+UUID) that is NOT a binary hash — the two are kept in distinct
// fields so neither is overloaded.
type ComponentState struct {
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	// SHA256 is the SHA-256 of the installed binary. It is empty when the
	// request does not carry an artifact hash (the CLI currently does not), in
	// which case the planner treats it as unasserted rather than fabricating a
	// value.
	SHA256 string `json:"sha256,omitempty"`
	// RealityFingerprint is the xray-only fingerprint of the PUBLIC Reality
	// parameters. It is preserved from the legacy overloaded sha256 field.
	RealityFingerprint string `json:"realityFingerprint,omitempty"`
}

// OriginState records the origin (T4) convergence identity. Every field is a
// value the origin package can actually produce from its Plan; CaddyfileHash is
// the SHA-256 of origin.RenderCaddyfile(plan) and is empty for modes that
// generate no Caddyfile (none, cdn plainOrigin).
type OriginState struct {
	Mode           string `json:"mode,omitempty"`
	Version        string `json:"version,omitempty"`
	Domain         string `json:"domain,omitempty"`
	UpstreamAddr   string `json:"upstreamAddr,omitempty"`
	OriginPort     int    `json:"originPort,omitempty"`
	ACMEChallenge  string `json:"acmeChallenge,omitempty"`
	ACMEEmail      string `json:"acmeEmail,omitempty"`
	CDNSecurity    string `json:"cdnSecurity,omitempty"`
	CDNOriginTrust string `json:"cdnOriginTrust,omitempty"`
	CaddyfileHash  string `json:"caddyfileHash,omitempty"`
}

// Paths records every managed path the host adapter actually uses. The fixed
// locations are derived from the authoritative internal/systemd constants (not
// re-declared), so a code change that moves a managed path becomes visible to
// the planner as drift.
type Paths struct {
	StateRoot      string `json:"stateRoot"`
	Env            string `json:"env,omitempty"`
	Config         string `json:"config,omitempty"`
	UnitDir        string `json:"unitDir,omitempty"`
	WantsDir       string `json:"wantsDir,omitempty"`
	LogDir         string `json:"logDir,omitempty"`
	DataDir        string `json:"dataDir,omitempty"`
	BinaryPrefix   string `json:"binaryPrefix,omitempty"`
	UnitsBackupDir string `json:"unitsBackupDir,omitempty"`
	// UnitFiles are the absolute unit-file paths this deployment owns, in the
	// canonical apply order.
	UnitFiles []string `json:"unitFiles,omitempty"`
	// BinaryPointer is the version-independent managed binary pointer (the xray
	// "current" symlink); empty for roles with no managed pointer.
	BinaryPointer string `json:"binaryPointer,omitempty"`
}

type PairingState struct {
	PeerRole     string   `json:"peerRole,omitempty"`
	State        string   `json:"state"`
	Fingerprints []string `json:"fingerprints,omitempty"`
}

// PairingStateNone is the pairing baseline a request expresses before any
// pairing has occurred. install is deliberately NOT authoritative over
// pairing: the committed pairing state is owned by the pair
// generate|apply|finalize commands, and Controller.ApplyRequest carries that
// committed state forward so a re-apply compares like-for-like instead of
// resetting it.
const PairingStateNone = "none"

// ServiceState records one managed unit. Hash is the SHA-256 of the rendered
// unit bytes (systemd.RenderUnit of the exact spec the apply path writes), so a
// changed unit file is detectable by the planner.
type ServiceState struct {
	Unit      string `json:"unit"`
	Component string `json:"component"`
	Hash      string `json:"hash"`
}

type FirewallState struct {
	Backend   string `json:"backend,omitempty"`
	Ownership string `json:"ownership,omitempty"`
	RulesHash string `json:"rulesHash,omitempty"`
}

type Revision struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Label     string    `json:"label"`
	Snapshot  string    `json:"snapshot"`
}

type DesiredState struct {
	Role       string
	Components Components
	Paths      Paths
	Pairing    PairingState
	Services   []ServiceState
	Firewall   FirewallState
}

type Change struct {
	Field       string
	Before      string
	After       string
	Destructive bool
}

type Plan struct {
	Changes   []Change
	Unchanged bool
}
