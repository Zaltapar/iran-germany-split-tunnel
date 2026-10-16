package dashboard

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestValidateOutboundAcceptsValid(t *testing.T) {
	o := OutboundConfig{Name: "de-reality", Protocol: "vless-reality", Port: 443,
		ServerName: "www.example.com", Transport: "tcp", Enabled: true}
	if errs := ValidateOutbound(o); len(errs) != 0 {
		t.Errorf("valid outbound rejected: %v", errs)
	}
}

func TestValidateOutboundRejectsInvalid(t *testing.T) {
	base := OutboundConfig{Name: "ok", Protocol: "vless-reality", Port: 443,
		ServerName: "www.example.com", Transport: "tcp"}
	cases := map[string]func(*OutboundConfig){
		"bad name":        func(o *OutboundConfig) { o.Name = "has space" },
		"bad protocol":    func(o *OutboundConfig) { o.Protocol = "socks" },
		"port zero":       func(o *OutboundConfig) { o.Port = 0 },
		"port too large":  func(o *OutboundConfig) { o.Port = 70000 },
		"sni leading dot": func(o *OutboundConfig) { o.ServerName = ".bad.example" },
		"sni with slash":  func(o *OutboundConfig) { o.ServerName = "a/b" },
		"bad transport":   func(o *OutboundConfig) { o.Transport = "udp" },
	}
	for name, mut := range cases {
		o := base
		mut(&o)
		if len(ValidateOutbound(o)) == 0 {
			t.Errorf("%s: accepted, want rejected", name)
		}
	}
}

func TestValidateRoutingRuleRules(t *testing.T) {
	cases := []struct {
		name string
		r    RoutingRule
		ok   bool
	}{
		{"direct domain", RoutingRule{ID: "r1", Match: "domain", Value: "example.ir", Action: "direct"}, true},
		{"tunnel cidr", RoutingRule{ID: "r2", Match: "ip_cidr", Value: "10.0.0.0/8", Action: "tunnel", Outbound: "de"}, true},
		{"tunnel without outbound", RoutingRule{ID: "r3", Match: "domain", Value: "a.com", Action: "tunnel"}, false},
		{"direct with outbound", RoutingRule{ID: "r4", Match: "domain", Value: "a.com", Action: "direct", Outbound: "de"}, false},
		{"bad cidr", RoutingRule{ID: "r5", Match: "ip_cidr", Value: "10.0.0.0/99", Action: "block"}, false},
		{"port out of range", RoutingRule{ID: "r6", Match: "port", Value: "70000", Action: "block"}, false},
		{"port leading zero", RoutingRule{ID: "r7", Match: "port", Value: "080", Action: "block"}, false},
		{"port valid", RoutingRule{ID: "r8", Match: "port", Value: "443", Action: "block"}, true},
		{"unknown action", RoutingRule{ID: "r9", Match: "domain", Value: "a.com", Action: "drop"}, false},
		{"bad id", RoutingRule{ID: "bad id", Match: "domain", Value: "a.com", Action: "block"}, false},
	}
	for _, c := range cases {
		errs := ValidateRoutingRule(c.r)
		if c.ok && len(errs) != 0 {
			t.Errorf("%s: rejected: %v", c.name, errs)
		}
		if !c.ok && len(errs) == 0 {
			t.Errorf("%s: accepted, want rejected", c.name)
		}
	}
}

func TestValidateRoutingPolicyCrossReferences(t *testing.T) {
	outs := []OutboundConfig{{Name: "de", Protocol: "vless-reality", Port: 443, ServerName: "a.example", Transport: "tcp"}}
	ok := RoutingPolicy{Mode: "split", Rules: []RoutingRule{
		{ID: "r1", Match: "domain", Value: "a.example", Action: "tunnel", Outbound: "de"},
	}}
	if errs := ValidateRoutingPolicy(ok, outs); len(errs) != 0 {
		t.Errorf("valid policy rejected: %v", errs)
	}
	unknown := RoutingPolicy{Mode: "split", Rules: []RoutingRule{
		{ID: "r1", Match: "domain", Value: "a.example", Action: "tunnel", Outbound: "missing"},
	}}
	if errs := ValidateRoutingPolicy(unknown, outs); len(errs) == 0 {
		t.Error("unknown outbound reference accepted")
	}
	dup := RoutingPolicy{Mode: "split", Rules: []RoutingRule{
		{ID: "r1", Match: "domain", Value: "a.com", Action: "block"},
		{ID: "r1", Match: "domain", Value: "b.com", Action: "block"},
	}}
	if errs := ValidateRoutingPolicy(dup, outs); len(errs) == 0 {
		t.Error("duplicate rule id accepted")
	}
	badMode := RoutingPolicy{Mode: "anything-goes"}
	if errs := ValidateRoutingPolicy(badMode, outs); len(errs) == 0 {
		t.Error("unknown mode accepted")
	}
}

func TestConfigValidateChecksV2Objects(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Outbounds = []OutboundConfig{
		{Name: "de", Protocol: "vless-reality", Port: 443, ServerName: "a.example", Transport: "tcp"},
		{Name: "de", Protocol: "vless-reality", Port: 8443, ServerName: "b.example", Transport: "tcp"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("duplicate outbound names must fail config validation")
	}

	cfg = DefaultConfig()
	cfg.Outbounds = []OutboundConfig{{Name: "de", Protocol: "vless-reality", Port: 443, ServerName: "a.example", Transport: "tcp"}}
	cfg.Routing = &RoutingPolicy{Mode: "split", Rules: []RoutingRule{
		{ID: "r1", Match: "domain", Value: "a.example", Action: "tunnel", Outbound: "nope"},
	}}
	if err := cfg.Validate(); err == nil {
		t.Error("routing referencing an unknown outbound must fail config validation")
	}
}

// TestConceptSchemaMatchesJSONTags pins the schema descriptors to the typed
// structs: every schema field must be a real json tag and every json tag must
// be described, so a future editor cannot drift from the wire shape.
func TestConceptSchemaMatchesJSONTags(t *testing.T) {
	types := map[string]reflect.Type{
		ConceptOutbound:      reflect.TypeOf(OutboundConfig{}),
		ConceptRoutingRule:   reflect.TypeOf(RoutingRule{}),
		ConceptRoutingPolicy: reflect.TypeOf(RoutingPolicy{}),
	}
	for _, sc := range ConceptSchemas() {
		typ, ok := types[sc.Concept]
		if !ok {
			t.Fatalf("schema for unknown concept %q", sc.Concept)
		}
		var tags, fields []string
		for i := 0; i < typ.NumField(); i++ {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				tags = append(tags, tag)
			}
		}
		for _, f := range sc.Fields {
			fields = append(fields, f.Name)
		}
		sort.Strings(tags)
		sort.Strings(fields)
		if !reflect.DeepEqual(tags, fields) {
			t.Errorf("%s: schema fields %v do not match json tags %v", sc.Concept, fields, tags)
		}
	}
}

// TestEditableTypesCarryNoSecretFields keeps secret material unrepresentable
// in the editable object model.
func TestEditableTypesCarryNoSecretFields(t *testing.T) {
	forbidden := []string{"key", "uuid", "password", "token", "secret", "pairing", "credential", "private"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(OutboundConfig{}), reflect.TypeOf(RoutingRule{}), reflect.TypeOf(RoutingPolicy{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name + typ.Field(i).Tag.Get("json"))
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s looks like secret material (%q)", typ.Name(), typ.Field(i).Name, bad)
				}
			}
		}
	}
}

func TestConceptSchemasAreReadOnlyStubs(t *testing.T) {
	for _, sc := range ConceptSchemas() {
		if sc.Editable {
			t.Errorf("%s: editable must be false in this phase", sc.Concept)
		}
		if sc.EditDisabledReason != "editing lands in the next phase" {
			t.Errorf("%s: disabled reason = %q", sc.Concept, sc.EditDisabledReason)
		}
		if sc.ValidationStatus != "stub" {
			t.Errorf("%s: validation status = %q, want stub", sc.Concept, sc.ValidationStatus)
		}
	}
}
