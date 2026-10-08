package xray

// consumerconfig.go — deterministic Iran Xray consumer config generation.
//
// RenderConsumerConfig produces the VLESS+Reality client config for the
// Iran-side Xray consumer unit (xray-consumer.service). The consumer is a
// dokodemo-door inbound (transparent TCP proxy) that forwards every
// connection to the Germany host's Reality inbound via a VLESS+Reality
// outbound. The public Reality parameters (public key, SNI, shortId, UUID)
// and the Germany down-host address come from Blob B (pairing.PublicParams
// + DownTarget); the local listen port is the SPLIT_DOWN_CARRIER_ADDR loopback
// port that iran-splitter dials.
//
// Security invariants:
//   - All operator inputs are validated before rendering (pairing validators);
//   - No private key material appears in the rendered config;
//   - Output is deterministic: same inputs → same bytes (golden-pinned);
//   - The config is a pure data file; the systemd unit gates the process.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// ErrInvalidConsumerParams is returned when the consumer parameters fail
// validation.
var ErrInvalidConsumerParams = errors.New("xray: consumer config: invalid parameters")

// ConsumerParams are the inputs to RenderConsumerConfig. They mirror the
// public fields of Blob B plus the local listen port.
type ConsumerParams struct {
	// PublicKey is the base64.RawURLEncoding 32-byte X25519 public key
	// (from Blob B's realityPublicKey).
	PublicKey string
	// SNI is the Reality camouflage domain (lowercase RFC 1123 hostname).
	SNI string
	// ShortID is the 16-hex Reality shortId.
	ShortID string
	// UUID is the RFC 4122 v4 client UUID.
	UUID string
	// DownHost is the Germany public host (IP or domain) for the
	// Reality inbound.
	DownHost string
	// DownPort is the Germany Reality inbound port (typically 443).
	DownPort int
	// ListenAddr is the loopback address the consumer binds (e.g. "127.0.0.1").
	ListenAddr string
	// ListenPort is the loopback port the consumer binds (the
	// SPLIT_DOWN_CARRIER_ADDR port the iran-splitter dials).
	ListenPort int
}

// ValidateConsumerParams checks all fields. Errors name fields, never values.
func ValidateConsumerParams(p ConsumerParams) error {
	var problems []string
	if !pairing.ValidSNI(p.SNI) {
		problems = append(problems, "sni: must be a lowercase RFC 1123 hostname")
	}
	if !pairing.ValidShortID(p.ShortID) {
		problems = append(problems, "shortId: must be 16 lowercase hex chars")
	}
	if !pairing.ValidUUID(p.UUID) {
		problems = append(problems, "uuid: must be an RFC 4122 version-4 UUID")
	}
	if p.PublicKey == "" {
		problems = append(problems, "publicKey: required (base64.RawURLEncoding 32-byte X25519)")
	}
	if !pairing.ValidUploadDomain(p.DownHost) {
		problems = append(problems, "downHost: must be a valid public host (IP or RFC 1123 domain)")
	}
	if p.DownPort < 1 || p.DownPort > 65535 {
		problems = append(problems, "downPort: must be 1..65535")
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		problems = append(problems, "listenPort: must be 1..65535")
	}
	if p.ListenAddr == "" {
		problems = append(problems, "listenAddr: required (loopback address)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidConsumerParams, strings.Join(problems, "; "))
}

// ---------------------------------------------------------------------------
// JSON shapes — struct declaration order IS the JSON key order. Do not add
// or reorder fields without regenerating the golden file on purpose.
// ---------------------------------------------------------------------------

type consumerConfig struct {
	Log       consumerLog     `json:"log"`
	Inbounds  []consumerInb   `json:"inbounds"`
	Outbounds []consumerOutb  `json:"outbounds"`
	Routing   consumerRouting `json:"routing"`
}

type consumerLog struct {
	LogLevel string `json:"loglevel"`
	Error    string `json:"error"`
}

type consumerInb struct {
	Tag      string              `json:"tag"`
	Listen   string              `json:"listen"`
	Port     int                 `json:"port"`
	Protocol string              `json:"protocol"`
	Settings consumerInbSettings `json:"settings"`
}

type consumerInbSettings struct {
	Network string `json:"network"`
}

type consumerOutb struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       consumerVLESS  `json:"settings"`
	StreamSettings consumerStream `json:"streamSettings"`
}

type consumerVLESS struct {
	VNext []consumerVNext `json:"vnext"`
}

type consumerVNext struct {
	Address string         `json:"address"`
	Port    int            `json:"port"`
	Users   []consumerUser `json:"users"`
}

type consumerUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}

type consumerStream struct {
	Network         string             `json:"network"`
	Security        string             `json:"security"`
	RealitySettings consumerRealityOut `json:"realitySettings"`
}

type consumerRealityOut struct {
	Dest       string `json:"dest"`
	ServerName string `json:"serverName"`
	PublicKey  string `json:"publicKey"`
	ShortID    string `json:"shortId"`
}

type consumerRouting struct {
	Rules []consumerRoute `json:"rules"`
}

type consumerRoute struct {
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// RenderConsumerConfig renders the Iran Xray consumer config from the
// validated public parameters. The output ends with a single trailing
// newline. It is a pure function: no I/O, no clock.
func RenderConsumerConfig(p ConsumerParams) ([]byte, error) {
	if err := ValidateConsumerParams(p); err != nil {
		return nil, err
	}

	cfg := consumerConfig{
		Log: consumerLog{
			LogLevel: "warning",
			Error:    "/var/log/split-tunnel/xray-consumer.error.log",
		},
		Inbounds: []consumerInb{{
			Tag:      "to-germany",
			Listen:   p.ListenAddr,
			Port:     p.ListenPort,
			Protocol: "dokodemo-door",
			Settings: consumerInbSettings{Network: "tcp"},
		}},
		Outbounds: []consumerOutb{{
			Tag:      "reality-germany",
			Protocol: "vless",
			Settings: consumerVLESS{
				VNext: []consumerVNext{{
					Address: p.DownHost,
					Port:    p.DownPort,
					Users: []consumerUser{{
						ID:         p.UUID,
						Encryption: "none",
					}},
				}},
			},
			StreamSettings: consumerStream{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: consumerRealityOut{
					Dest:       p.SNI + ":443",
					ServerName: p.SNI,
					PublicKey:  p.PublicKey,
					ShortID:    p.ShortID,
				},
			},
		}},
		Routing: consumerRouting{
			Rules: []consumerRoute{{
				InboundTag:  []string{"to-germany"},
				OutboundTag: "reality-germany",
			}},
		},
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("xray: consumer config: render: %w", err)
	}
	return append(b, '\n'), nil
}

// ConsumerConfigFromBlobB extracts the consumer parameters from a parsed
// Blob B and the operator-chosen local listen port. This is the primary
// entry point for the installer: Blob B carries the public Reality params
// and the Germany down-target; the local listen port comes from the
// SPLIT_DOWN_CARRIER_ADDR env var (the loopback port iran-splitter dials).
func ConsumerConfigFromBlobB(b *pairing.BlobB, listenAddr string, listenPort int) ([]byte, error) {
	p := ConsumerParams{
		PublicKey:  b.Public.RealityPublicKey,
		SNI:        b.Public.SNI,
		ShortID:    b.Public.ShortID,
		UUID:       b.Public.UUID,
		DownHost:   b.Germany.Host,
		DownPort:   b.Germany.Port,
		ListenAddr: listenAddr,
		ListenPort: listenPort,
	}
	return RenderConsumerConfig(p)
}

// EnsureListenPortValid is a helper for tests and the installer: it
// validates the listen port independently.
func EnsureListenPortValid(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("xray: consumer listen port %d out of range 1..%d", port, 65535)
	}
	return nil
}

// ConsumerPortStr returns the port as a string for use in SPLIT_DOWN_CARRIER_ADDR.
func ConsumerPortStr(port int) string { return strconv.Itoa(port) }
