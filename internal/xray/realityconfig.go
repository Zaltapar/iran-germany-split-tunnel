package xray

// realityconfig.go — deterministic Germany Xray config generation
// (architecture doc §4.5, task T3).
//
// RenderGermanyConfig is a PURE function of (validated operator params,
// keypair encodings): no timestamps, no maps iterated for output, fixed
// struct field order (= fixed JSON key order), 2-space indent, trailing
// newline. The same logical input always produces byte-identical output;
// the exact bytes are pinned by testdata/golden/germany-config.golden.json.
//
// Security invariants:
//   - operator inputs (SNI / shortId / uuid) are validated BEFORE rendering,
//     reusing the single source of truth in internal/pairing (no duplicated
//     validation rules);
//   - every error names the offending FIELD, never the value — no key
//     material or operator input is ever echoed into an error string;
//   - values land in the JSON via encoding/json escaping, never via string
//     concatenation (an SNI containing a quote cannot break out of its
//     string literal);
//   - the Reality PRIVATE key is written into the config (0600 at
//     activation, doc §4.4) but never into any pairing blob, log line, or
//     error;
//   - 9002 appears ONLY as the loopback target 127.0.0.1:9002 (the freedom
//     outbound's settings.redirect); the only public listener in the
//     generated config is the Reality inbound 0.0.0.0:443.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// Error sentinels. All wrapped errors carry field names and rule text
// only — never field values.
var (
	ErrInvalidParams = errors.New("xray: reality config: invalid operator parameters")
	// ErrMissingKeypair: no key material was supplied at all (nil or
	// zero-value keypair).
	ErrMissingKeypair = errors.New("xray: reality config: Reality key material is missing")
	// ErrBadKeypair: key material was supplied but fails strict decoding
	// (not base64.RawURLEncoding, or not exactly 32 bytes).
	ErrBadKeypair = errors.New("xray: reality config: Reality key material failed validation")
)

// RealityParams are the operator-supplied Germany values for the Reality
// inbound. They are exactly the values that also travel in the T1 pairing
// blob B (public side), so both sides validate them with the same rules.
type RealityParams struct {
	// SNI is the TLS ServerName / Reality camouflage domain
	// (lowercase RFC 1123 hostname, no IP literal). It is used for
	// serverNames AND derived into dest = "<SNI>:443".
	SNI string
	// ShortID is the 16-hex-char Reality shortId (lowercase).
	ShortID string
	// UUID is the single VLESS client id (RFC 4122 v4, lowercase),
	// generated on Germany.
	UUID string
}

// Fixed topology constants (doc §4.5). They are NOT operator-tunable in
// T3: the Reality inbound listens on 0.0.0.0:443 and forwards every
// stream to the splitter down-carrier listener 127.0.0.1:9002.
// (Operator port choice for the down carrier arrives with T5.)
const (
	germanyListen   = "0.0.0.0"
	germanyPort     = 443
	splitterAddress = "127.0.0.1"
	splitterPort    = 9002
	tagSplitDown    = "split-down"
	tagToSplitter   = "to-splitter"
	xrayErrorLog    = "/var/log/split-tunnel/xray-germany.error.log"

	// Phase 2 multi-carrier (D1/D3): the SECOND VLESS+Reality instance.
	// Instance b listens on its own public port with its own SNI/shortId/UUID
	// and keypair, and its routing points to its own loopback splitter
	// down-carrier listener (127.0.0.1:9003), distinct from instance a's
	// 127.0.0.1:9002. The public port is D3 (2053, never the dashboard-reserved
	// 8443). These constants are topology-fixed like the primary's.
	secondDownPublicPort = 2053
	secondSplitterPort   = 9003
	tagSplitDownB        = "split-down-b"
	tagToSplitterB       = "to-splitter-b"
)

// ValidateRealityParams exposes pure Reality input validation to deployment
// orchestration. It performs no filesystem, process, or network operations.
func ValidateRealityParams(p RealityParams) error { return p.validate() }

// validate reports the first aggregated problem set (field names + rule
// text only, never values).
func (p RealityParams) validate() error {
	var problems []string
	if !pairing.ValidSNI(p.SNI) {
		problems = append(problems, "sni: must be a lowercase RFC 1123 hostname (no IP literal, no port, no scheme)")
	}
	if !pairing.ValidShortID(p.ShortID) {
		problems = append(problems, "shortId: must be 16 lowercase hex chars")
	}
	if !pairing.ValidUUID(p.UUID) {
		problems = append(problems, "uuid: must be an RFC 4122 version-4 UUID (lowercase)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidParams, strings.Join(problems, "; "))
}

// checkKeypair verifies the key material is present and strictly decodable
// (base64.RawURLEncoding, exactly 32 bytes per key — the format the pinned
// Xray config loader requires). It does NOT re-verify the X25519 clamp;
// that was keygen's job. The check is fail-closed: a hand-built or
// truncated keypair can never reach the rendered config.
func checkKeypair(kp *Keypair) error {
	if kp == nil || kp.PrivateRaw == "" {
		return ErrMissingKeypair
	}
	if _, err := decodeKey32(kp.PrivateRaw); err != nil {
		return fmt.Errorf("%w: privateKey", ErrBadKeypair)
	}
	if _, err := decodeKey32(kp.PublicRaw); err != nil {
		return fmt.Errorf("%w: publicKey", ErrBadKeypair)
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON shapes — struct declaration order IS the JSON key order. Do not add
// or reorder fields without regenerating the golden file on purpose.
// ---------------------------------------------------------------------------

type germanyConfig struct {
	Log       germanyLog        `json:"log"`
	Inbounds  []germanyInbound  `json:"inbounds"`
	Outbounds []germanyOutbound `json:"outbounds"`
	Routing   germanyRouting    `json:"routing"`
}

type germanyLog struct {
	LogLevel string `json:"loglevel"`
	Error    string `json:"error"`
}

type germanyInbound struct {
	Tag            string                `json:"tag"`
	Listen         string                `json:"listen"`
	Port           int                   `json:"port"`
	Protocol       string                `json:"protocol"`
	Settings       vlessInboundSettings  `json:"settings"`
	StreamSettings germanyStreamSettings `json:"streamSettings"`
}

type vlessInboundSettings struct {
	Clients    []vlessClient `json:"clients"`
	Decryption string        `json:"decryption"`
}

type vlessClient struct {
	ID string `json:"id"`
}

type germanyStreamSettings struct {
	Network  string                  `json:"network"`
	Security string                  `json:"security"`
	Reality  *germanyRealitySettings `json:"realitySettings"`
}

type germanyRealitySettings struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
}

type germanyOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings freedomSettings `json:"settings"`
}

// freedomSettings mirrors xray-core v26.3.27 infra/conf/freedom.go FreedomConfig
// (only the fields this config uses; unknown fields are ignored by the
// binary, but we emit only the redirect).
type freedomSettings struct {
	Redirect string `json:"redirect"`
}

type germanyRouting struct {
	Rules []germanyRoutingRule `json:"rules"`
}

type germanyRoutingRule struct {
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// RenderGermanyConfig renders the Germany Xray config (doc §4.5) for the
// validated params and keypair:
//
//	inbound  "split-down"  vless + reality   0.0.0.0:443
//	routing  split-down    → to-splitter
//	outbound "to-splitter" freedom redirect  127.0.0.1:9002
//
// Deliberate omissions (doc §4.5): no flow (server side), no sniffing
// (opaque TCP must not be sniffed or have its dest overridden), no extra
// outbounds. The output ends with a single trailing newline.
//
// The outbound is freedom-with-redirect, NOT dokodemo-door: at the pinned
// Xray v26.3.27 tag, dokodemo-door is registered as an INBOUND protocol
// only (infra/conf/xray.go inboundConfigLoader); it is absent from the
// outbound loader, so "unknown config id: dokodemo-door" fails
// xray run -test. freedom's settings.redirect sets a DestinationOverride
// that forces every connection's dial target to the fixed endpoint
// (proxy/freedom/freedom.go), which is exactly the opaque-TCP hand-off to
// the splitter down-carrier that dokodemo-door would have provided.
func RenderGermanyConfig(p RealityParams, kp *Keypair) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if err := checkKeypair(kp); err != nil {
		return nil, err
	}

	cfg := germanyConfig{
		Log: germanyLog{
			LogLevel: "warning",
			Error:    xrayErrorLog,
		},
		Inbounds: []germanyInbound{{
			Tag:      tagSplitDown,
			Listen:   germanyListen,
			Port:     germanyPort,
			Protocol: "vless",
			Settings: vlessInboundSettings{
				Clients:    []vlessClient{{ID: p.UUID}},
				Decryption: "none",
			},
			StreamSettings: germanyStreamSettings{
				Network:  "tcp",
				Security: "reality",
				Reality: &germanyRealitySettings{
					// dest is DERIVED, never operator input: the
					// camouflage target is the SNI itself on 443.
					Dest:        p.SNI + ":443",
					ServerNames: []string{p.SNI},
					PrivateKey:  kp.PrivateRaw,
					ShortIds:    []string{p.ShortID},
				},
			},
		}},
		Outbounds: []germanyOutbound{{
			Tag:      tagToSplitter,
			Protocol: "freedom",
			Settings: freedomSettings{
				// redirect forces the freedom outbound's dial target to
				// the fixed splitter down-carrier endpoint (opaque TCP
				// hand-off); see the function doc for why dokodemo-door
				// is not usable as an outbound at the pinned tag.
				Redirect: splitterAddress + ":" + strconv.Itoa(splitterPort),
			},
		}},
		Routing: germanyRouting{
			Rules: []germanyRoutingRule{{
				InboundTag:  []string{tagSplitDown},
				OutboundTag: tagToSplitter,
			}},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray: reality config: render: %w", err)
	}
	return append(b, '\n'), nil
}

// RealityInstance describes ONE VLESS+Reality instance. Instance a uses the
// primary topology constants; instance b (Phase 2, D1/D3) uses the second's
// public port + loopback listener. Each instance carries its own SNI, shortId,
// UUID, and (for the Germany side) Reality keypair.
type RealityInstance struct {
	RealityParams
	// PubPort is the public listen port for this instance. Omitted (0) renders
	// the topology-fixed primary port (germanyPort) for instance a; instance
	// b must set it explicitly (e.g. secondDownPublicPort).
	PubPort int
	// SplitPort is the loopback splitter down-carrier port this instance's
	// outbound freedom-redirect points at. Omitted (0) renders splitterPort.
	SplitPort int
	// Tags are the Xray inbound/outbound/route tags for this instance. Omitted
	// tags render the primary constants; instance b must set distinct ones.
	InboundTag  string
	OutboundTag string
	// Keypair is the per-instance Reality key material (Germany side only).
	// It is required for the Germany multi-renderer.
	Keypair *Keypair
}

// MultiInstanceParams is the validated input for the multi-carrier Germany
// render: instance a (primary) plus instance b (second). Both are fully
// validated with the single-instance rules; b additionally requires its own
// public port (≠ a's, ≠ 8443) and a distinct SNI (D3).
type MultiInstanceParams struct {
	A RealityInstance
	B RealityInstance
}

// ValidateMultiInstanceParams validates both instances for the multi-carrier
// Germany config. It enforces the single-instance rules for each, plus the
// Phase 2 instance-b invariants: b's public port is set, not 8443 (dashboard-
// reserved), and differs from a's; b's SNI is a valid TLS 1.3 domain; and b
// carries its own keypair. Errors name fields, never values.
func ValidateMultiInstanceParams(p MultiInstanceParams) error {
	if err := p.A.RealityParams.validate(); err != nil {
		return fmt.Errorf("xray: reality config: instance a: %w", err)
	}
	if err := p.B.RealityParams.validate(); err != nil {
		return fmt.Errorf("xray: reality config: instance b: %w", err)
	}
	if err := checkKeypair(p.A.Keypair); err != nil {
		return fmt.Errorf("xray: reality config: instance a keypair: %w", err)
	}
	if err := checkKeypair(p.B.Keypair); err != nil {
		return fmt.Errorf("xray: reality config: instance b keypair: %w", err)
	}
	var problems []string
	if p.B.PubPort < 1 || p.B.PubPort > 65535 {
		problems = append(problems, "instance b: pubPort must be 1..65535")
	}
	if p.B.PubPort == 8443 {
		problems = append(problems, "instance b: pubPort 8443 is reserved for the dashboard TLS listener")
	}
	if p.B.PubPort == p.A.PubPort {
		problems = append(problems, "instance b: pubPort must differ from instance a (distinct listener)")
	}
	if p.B.SNI == p.A.SNI {
		problems = append(problems, "instance b: sni must differ from instance a (a distinct TLS 1.3 SNI, D3)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidParams, strings.Join(problems, "; "))
}

// renderInstance builds the (inbound, outbound, route) triplet for one
// Reality instance, honoring its topology overrides.
func renderInstance(in RealityInstance) (germanyInbound, germanyOutbound, germanyRoutingRule) {
	pubPort := in.PubPort
	if pubPort == 0 {
		pubPort = germanyPort
	}
	splitPort := in.SplitPort
	if splitPort == 0 {
		splitPort = splitterPort
	}
	inboundTag := in.InboundTag
	if inboundTag == "" {
		inboundTag = tagSplitDown
	}
	outTag := in.OutboundTag
	if outTag == "" {
		outTag = tagToSplitter
	}
	inb := germanyInbound{
		Tag:      inboundTag,
		Listen:   germanyListen,
		Port:     pubPort,
		Protocol: "vless",
		Settings: vlessInboundSettings{
			Clients:    []vlessClient{{ID: in.UUID}},
			Decryption: "none",
		},
		StreamSettings: germanyStreamSettings{
			Network:  "tcp",
			Security: "reality",
			Reality: &germanyRealitySettings{
				Dest:        in.SNI + ":443",
				ServerNames: []string{in.SNI},
				PrivateKey:  in.Keypair.PrivateRaw,
				ShortIds:    []string{in.ShortID},
			},
		},
	}
	ob := germanyOutbound{
		Tag:      outTag,
		Protocol: "freedom",
		Settings: freedomSettings{
			Redirect: splitterAddress + ":" + strconv.Itoa(splitPort),
		},
	}
	rule := germanyRoutingRule{
		InboundTag:  []string{inboundTag},
		OutboundTag: outTag,
	}
	return inb, ob, rule
}

// RenderGermanyMultiConfig renders the two-instance Germany Xray config
// (Phase 2, D1/D3): two VLESS+Reality inbounds (instance a on 443, instance
// b on its public port), each routing to its own loopback splitter listener
// (9002 / 9003). It is a pure, deterministic function: fixed struct field
// order, 2-space indent, trailing newline; the same input always yields the
// same bytes (golden-pinned). The single-carrier golden is UNCHANGED — this
// is a distinct function that only the multi-carrier path calls.
func RenderGermanyMultiConfig(p MultiInstanceParams) ([]byte, error) {
	if err := ValidateMultiInstanceParams(p); err != nil {
		return nil, err
	}
	inA, obA, ruleA := renderInstance(p.A)
	inB, obB, ruleB := renderInstance(p.B)

	cfg := germanyConfig{
		Log: germanyLog{
			LogLevel: "warning",
			Error:    xrayErrorLog,
		},
		Inbounds:  []germanyInbound{inA, inB},
		Outbounds: []germanyOutbound{obA, obB},
		Routing: germanyRouting{
			Rules: []germanyRoutingRule{ruleA, ruleB},
		},
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray: reality config: render multi: %w", err)
	}
	return append(b, '\n'), nil
}
