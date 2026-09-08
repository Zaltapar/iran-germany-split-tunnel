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
//   - 9002 appears ONLY as the loopback dokodemo-door target
//     127.0.0.1:9002; the only public listener in the generated config is
//     the Reality inbound 0.0.0.0:443.

import (
	"encoding/json"
	"errors"
	"fmt"
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
)

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
	Tag      string           `json:"tag"`
	Protocol string           `json:"protocol"`
	Settings dokodemoSettings `json:"settings"`
}

type dokodemoSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
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
//	outbound "to-splitter" dokodemo-door     127.0.0.1:9002
//
// Deliberate omissions (doc §4.5): no flow (server side), no sniffing
// (opaque TCP must not be sniffed or have its dest overridden), no extra
// outbounds. The output ends with a single trailing newline.
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
			Protocol: "dokodemo-door",
			Settings: dokodemoSettings{
				Address: splitterAddress,
				Port:    splitterPort,
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
