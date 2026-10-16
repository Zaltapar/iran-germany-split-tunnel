package dashboard

// api_v2_schema.go — typed, editing-ready configuration objects for Dashboard
// v2.
//
// Phase scope: READ-ONLY. Nothing in this file mutates state or is reachable
// by a write route. Each editable concept (outbound / Reality entry, routing
// rule, routing policy) is represented here as:
//
//   - a typed Go struct with json tags (the wire shape),
//   - a pure validation function (the rules a future write path must pass),
//   - a schema descriptor served read-only under /api/v2/schema/{concept},
//     which the UI uses to render disabled controls.
//
// The validation endpoint /api/v2/validate/{concept} is a STUB in this phase:
// it answers 405 with an explanatory body, so a POST to any v2 route cannot
// change anything. The pure validators below are unit-tested directly.
//
// These structs deliberately have NO fields for private keys, UUIDs/user
// credentials, pairing secrets, or tokens. Secret material must never be
// representable in a config object that the dashboard can display.

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Editable concept names (URL path segments under /api/v2/schema/).
const (
	ConceptOutbound      = "outbound"
	ConceptRoutingRule   = "routing-rule"
	ConceptRoutingPolicy = "routing-policy"
)

// Enumerations shared by the typed objects and their schemas.
var (
	outboundProtocols  = []string{"vless-reality"}
	outboundTransports = []string{"tcp", "grpc", "ws"}
	routingMatchKinds  = []string{"domain", "ip_cidr", "port"}
	routingActions     = []string{"direct", "tunnel", "block"}
	routingModes       = []string{"split", "full-tunnel", "direct-only"}
)

const (
	maxRoutingRules  = 256
	maxNameLen       = 64
	maxSNILen        = 253
	maxRouteValueLen = 253
)

var (
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)
	snilPattern  = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)
	routeIDPatt  = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)
	routeValPatt = regexp.MustCompile(`^[A-Za-z0-9.\-:/_]{1,253}$`)
)

// OutboundConfig describes one configured Reality/Xray outbound. Only
// non-secret, display-safe fields exist: the public-facing identity of the
// outbound (name, port, SNI, transport) and its enablement.
type OutboundConfig struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"` // TLS SNI presented to the peer
	Transport  string `json:"transport"`
	Enabled    bool   `json:"enabled"`
}

// RoutingRule is one split-tunnel routing rule. Match selects traffic by
// domain suffix, CIDR, or destination port; Action decides its path.
type RoutingRule struct {
	ID     string `json:"id"`
	Match  string `json:"match"`
	Value  string `json:"value"`
	Action string `json:"action"`
	// Outbound names the outbound used when Action is "tunnel".
	Outbound string `json:"outbound,omitempty"`
}

// RoutingPolicy is the routing view: a mode plus an ordered rule list.
type RoutingPolicy struct {
	Mode  string        `json:"mode"`
	Rules []RoutingRule `json:"rules"`
}

// ValidateOutbound returns every rule violation for o (empty = valid). It is
// pure and performs no I/O.
func ValidateOutbound(o OutboundConfig) []string {
	var errs []string
	if !namePattern.MatchString(o.Name) {
		errs = append(errs, "name must be 1-64 chars of [A-Za-z0-9_.-]")
	}
	if !containsString(outboundProtocols, o.Protocol) {
		errs = append(errs, "protocol must be one of "+strings.Join(outboundProtocols, ", "))
	}
	if o.Port < 1 || o.Port > 65535 {
		errs = append(errs, "port must be in 1..65535")
	}
	if !snilPattern.MatchString(o.ServerName) || strings.HasPrefix(o.ServerName, ".") || strings.HasSuffix(o.ServerName, ".") {
		errs = append(errs, "serverName must be a hostname of [A-Za-z0-9.-] (max 253)")
	}
	if !containsString(outboundTransports, o.Transport) {
		errs = append(errs, "transport must be one of "+strings.Join(outboundTransports, ", "))
	}
	return errs
}

// ValidateRoutingRule returns every rule violation for r. It does not check
// that Outbound exists; that cross-object check belongs to ValidateRoutingPolicy.
func ValidateRoutingRule(r RoutingRule) []string {
	var errs []string
	if !routeIDPatt.MatchString(r.ID) {
		errs = append(errs, "id must be 1-64 chars of [A-Za-z0-9_-]")
	}
	if !containsString(routingMatchKinds, r.Match) {
		errs = append(errs, "match must be one of "+strings.Join(routingMatchKinds, ", "))
	}
	if !containsString(routingActions, r.Action) {
		errs = append(errs, "action must be one of "+strings.Join(routingActions, ", "))
	}
	switch r.Match {
	case "ip_cidr":
		if _, _, err := net.ParseCIDR(r.Value); err != nil {
			errs = append(errs, "value must be a valid CIDR for match ip_cidr")
		}
	case "port":
		var p int
		if _, err := fmt.Sscanf(r.Value, "%d", &p); err != nil || p < 1 || p > 65535 || fmt.Sprint(p) != r.Value {
			errs = append(errs, "value must be a port number 1..65535 for match port")
		}
	case "domain":
		if !routeValPatt.MatchString(r.Value) {
			errs = append(errs, "value must be a domain of [A-Za-z0-9.-] (max 253)")
		}
	}
	if r.Action == "tunnel" && r.Outbound == "" {
		errs = append(errs, "outbound is required when action is tunnel")
	}
	if r.Action != "tunnel" && r.Outbound != "" {
		errs = append(errs, "outbound must be empty unless action is tunnel")
	}
	return errs
}

// ValidateRoutingPolicy checks the mode, each rule, rule-ID uniqueness, the
// rule cap, and that every tunnel rule references a known outbound name.
func ValidateRoutingPolicy(p RoutingPolicy, outbounds []OutboundConfig) []string {
	var errs []string
	if !containsString(routingModes, p.Mode) {
		errs = append(errs, "mode must be one of "+strings.Join(routingModes, ", "))
	}
	if len(p.Rules) > maxRoutingRules {
		errs = append(errs, fmt.Sprintf("at most %d rules are allowed", maxRoutingRules))
	}
	known := map[string]bool{}
	for _, o := range outbounds {
		known[o.Name] = true
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		for _, e := range ValidateRoutingRule(r) {
			errs = append(errs, fmt.Sprintf("rules[%d]: %s", i, e))
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Sprintf("rules[%d]: duplicate id %q", i, r.ID))
		}
		seen[r.ID] = true
		if r.Action == "tunnel" && r.Outbound != "" && !known[r.Outbound] {
			errs = append(errs, fmt.Sprintf("rules[%d]: unknown outbound %q", i, r.Outbound))
		}
	}
	return errs
}

// FieldSchema describes one field of a concept for the read-only schema view.
type FieldSchema struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Enum     []string `json:"enum,omitempty"`
	Min      int      `json:"min,omitempty"`
	Max      int      `json:"max,omitempty"`
	MaxLen   int      `json:"maxLength,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
}

// ConceptSchema is the read-only schema document for one editable concept.
type ConceptSchema struct {
	Concept            string        `json:"concept"`
	Fields             []FieldSchema `json:"fields"`
	Editable           bool          `json:"editable"`
	Status             string        `json:"status"`
	EditDisabledReason string        `json:"editDisabledReason"`
	ValidationEndpoint string        `json:"validationEndpoint"`
	ValidationStatus   string        `json:"validationStatus"`
}

// editDisabledReason is shown as the tooltip on every disabled Apply control.
const editDisabledReason = "editing lands in the next phase"

// ConceptSchemas returns the schema documents for all editable concepts, in
// a stable order. Every field's JSON name must match a struct json tag; a
// unit test enforces that.
func ConceptSchemas() []ConceptSchema {
	mk := func(concept string, fields []FieldSchema) ConceptSchema {
		return ConceptSchema{
			Concept:            concept,
			Fields:             fields,
			Editable:           false,
			Status:             "read-only",
			EditDisabledReason: editDisabledReason,
			ValidationEndpoint: "/api/v2/validate/" + concept,
			ValidationStatus:   "stub",
		}
	}
	return []ConceptSchema{
		mk(ConceptOutbound, []FieldSchema{
			{Name: "name", Type: "string", Required: true, MaxLen: maxNameLen, Pattern: namePattern.String()},
			{Name: "protocol", Type: "enum", Required: true, Enum: outboundProtocols},
			{Name: "port", Type: "int", Required: true, Min: 1, Max: 65535},
			{Name: "serverName", Type: "string", Required: true, MaxLen: maxSNILen, Pattern: snilPattern.String()},
			{Name: "transport", Type: "enum", Required: true, Enum: outboundTransports},
			{Name: "enabled", Type: "bool", Required: false},
		}),
		mk(ConceptRoutingRule, []FieldSchema{
			{Name: "id", Type: "string", Required: true, MaxLen: 64, Pattern: routeIDPatt.String()},
			{Name: "match", Type: "enum", Required: true, Enum: routingMatchKinds},
			{Name: "value", Type: "string", Required: true, MaxLen: maxRouteValueLen},
			{Name: "action", Type: "enum", Required: true, Enum: routingActions},
			{Name: "outbound", Type: "string", Required: false, MaxLen: maxNameLen},
		}),
		mk(ConceptRoutingPolicy, []FieldSchema{
			{Name: "mode", Type: "enum", Required: true, Enum: routingModes},
			{Name: "rules", Type: "array", Required: false, Max: maxRoutingRules},
		}),
	}
}

// conceptSchemaByName returns the schema for concept, or false when unknown.
func conceptSchemaByName(concept string) (ConceptSchema, bool) {
	for _, c := range ConceptSchemas() {
		if c.Concept == concept {
			return c, true
		}
	}
	return ConceptSchema{}, false
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
