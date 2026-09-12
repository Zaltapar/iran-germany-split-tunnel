// Package deploy owns deployment desired-state planning and persistent state.
// It is deliberately above the transport engine and below cmd/splitterctl.
package deploy

import "time"

const SchemaVersion = 1

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

type ComponentState struct {
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

type OriginState struct {
	Mode    string `json:"mode,omitempty"`
	Version string `json:"version,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

type Paths struct {
	StateRoot string `json:"stateRoot"`
	Env       string `json:"env,omitempty"`
	Config    string `json:"config,omitempty"`
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
