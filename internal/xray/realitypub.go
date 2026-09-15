package xray

// realitypub.go — read-back of the Germany host's INSTALLED Reality
// parameters, for the pairing return blob (architecture doc §6.1: `splitterctl
// pair apply` on Germany consumes Blob A and must emit Blob B).
//
// Blob B must carry the EXACT Reality public key matching the installed
// inbound — a freshly generated keypair would silently break every existing
// Iran outbound. The keypair is recorded nowhere else: the manifest stores
// only the public-parameter fingerprint (SNI+shortId+UUID), and the rendered
// config (§4.5) embeds ONLY the private key (Xray derives the public key from
// it at load time). So this reader re-derives the public key from the
// installed privateKey via standard X25519 scalar*base-point (crypto/ecdh);
// it never generates anything and never mutates anything.
//
// Secret hygiene (doc §8): the private key bytes never leave
// ReadInstalledRealityParams — the returned value carries the DERIVED public
// key plus the inbound's public fields only. No error echoes config content:
// JSON decode errors are collapsed to a sentinel (Go's decoder can quote
// offending bytes), key-material errors name the field only, and read errors
// carry the path (already recorded in the manifest) — never file bytes.

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// Read-back failures. None include config content or key material.
var ErrInstalledConfigRead = errors.New("xray: installed Germany Reality config cannot be read")

var ErrInstalledConfig = errors.New("xray: installed Germany Reality config is not a valid Reality inbound")

var ErrInstalledKey = errors.New("xray: installed Germany Reality private key failed validation")

// InstalledRealityParams is the read-back of the live Germany config: the
// inbound's public parameters plus the Reality public key DERIVED from its
// private key — exactly the material Blob B carries (public only).
type InstalledRealityParams struct {
	// RealityPublicKey is base64 StdEncoding (32-byte X25519 point) — the
	// format the pairing blob requires.
	RealityPublicKey string
	// SNI is the inbound's single realitySettings.serverNames entry.
	SNI string
	// ShortID is the inbound's single realitySettings.shortIds entry.
	ShortID string
	// UUID is the inbound's single vless client id.
	UUID string
	// Port is the inbound port (Germany's public down port).
	Port int
}

// ReadInstalledRealityParams parses the live Germany Xray config at path
// (the manifest's Paths.Config, normally /etc/split-tunnel/xray-germany.json,
// 0600 root-owned) and derives its Reality public key. It performs no host
// mutation and derives nothing beyond the X25519 public point.
//
// The config is decoded generically (map[string]any): unknown fields are
// deliberately TOLERATED — xray's own loader ignores what it does not know,
// and Blob B re-emission must survive future config additions. But every
// field Blob B needs must be present, singular, and valid; the reader fails
// closed on anything ambiguous rather than emitting a wrong hand-off.
func ReadInstalledRealityParams(path string) (*InstalledRealityParams, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty config path", ErrInstalledConfigRead)
	}
	// The 0600 live config must be a real file we read directly: a symlink or
	// special file at a path we did not render is a refusal, not an open.
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInstalledConfigRead, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: config path is not a regular file", ErrInstalledConfigRead)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInstalledConfigRead, err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		// Collapse the decoder error: Go can quote offending bytes, and a
		// corrupt config's bytes may include key material.
		return nil, fmt.Errorf("%w: config is not valid JSON for this shape", ErrInstalledConfig)
	}
	inbounds, _ := arrayOf(root["inbounds"])

	var matched bool
	params := &InstalledRealityParams{}
	for _, raw := range inbounds {
		in, ok := objectOf(raw)
		if !ok {
			continue
		}
		if stringValue(in, "protocol") != "vless" {
			continue
		}
		stream, ok := objectOf(in["streamSettings"])
		if !ok || stringValue(stream, "security") != "reality" {
			continue
		}
		reality, ok := objectOf(stream["realitySettings"])
		if !ok {
			return nil, fmt.Errorf("%w: streamSettings.security is reality but realitySettings is absent or not an object", ErrInstalledConfig)
		}
		if matched {
			// The generated config has exactly one Reality inbound; more is
			// an ambiguous hand-off source and fails closed.
			return nil, fmt.Errorf("%w: more than one Reality vless inbound found, exactly 1 required", ErrInstalledConfig)
		}
		matched = true

		port, ok := intValue(in["port"])
		if !ok || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%w: Reality inbound port is missing or out of range", ErrInstalledConfig)
		}
		settings, ok := objectOf(in["settings"])
		if !ok {
			return nil, fmt.Errorf("%w: inbound settings must be an object", ErrInstalledConfig)
		}
		clients, ok := arrayOf(settings["clients"])
		if !ok || len(clients) != 1 {
			return nil, fmt.Errorf("%w: Reality inbound must carry exactly 1 client", ErrInstalledConfig)
		}
		client, ok := objectOf(clients[0])
		if !ok {
			return nil, fmt.Errorf("%w: inbound client must be an object", ErrInstalledConfig)
		}
		uuid := stringValue(client, "id")
		if !pairing.ValidUUID(uuid) {
			return nil, fmt.Errorf("%w: inbound client id is not a lowercase RFC 4122 v4 UUID", ErrInstalledConfig)
		}
		serverNames, ok := arrayOf(reality["serverNames"])
		if !ok || len(serverNames) != 1 {
			return nil, fmt.Errorf("%w: realitySettings.serverNames must hold exactly one valid SNI", ErrInstalledConfig)
		}
		sni, ok := serverNames[0].(string)
		if !ok || !pairing.ValidSNI(sni) {
			return nil, fmt.Errorf("%w: realitySettings.serverNames must hold exactly one valid SNI", ErrInstalledConfig)
		}
		shortIDs, ok := arrayOf(reality["shortIds"])
		if !ok || len(shortIDs) != 1 {
			return nil, fmt.Errorf("%w: realitySettings.shortIds must hold exactly one valid shortId", ErrInstalledConfig)
		}
		shortID, ok := shortIDs[0].(string)
		if !ok || !pairing.ValidShortID(shortID) {
			return nil, fmt.Errorf("%w: realitySettings.shortIds must hold exactly one valid shortId", ErrInstalledConfig)
		}
		priv, err := decodeKey32(stringValue(reality, "privateKey"))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInstalledKey, err)
		}
		// Derive (never regenerate) the public key matching the installed
		// inbound. ecdh's validation errors never quote key bytes.
		key, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("%w: privateKey rejected: %v", ErrInstalledKey, err)
		}
		params.RealityPublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		params.SNI = sni
		params.ShortID = shortID
		params.UUID = uuid
		params.Port = port
	}
	if !matched {
		return nil, fmt.Errorf("%w: no Reality vless inbound found", ErrInstalledConfig)
	}
	return params, nil
}

func objectOf(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func arrayOf(v any) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok
}

func stringValue(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func intValue(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	n := int(f)
	if float64(n) != f {
		return 0, false
	}
	return n, true
}
