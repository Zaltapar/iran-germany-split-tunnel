// Package config is the centralized configuration-loading and validation
// layer for both splitter binaries (Phase 7).
//
// The lifecycle is strictly ordered:
//
//	load (env → defaults)  →  parse  →  validate  →  construct runtime
//
// A binary must not open a listener, dial a carrier or start worker
// goroutines until config.Load has returned successfully; Load reports
// ALL validation problems at once (error aggregation) so operators do
// not have to fix-one-error-restart repeatedly.
//
// Environment-variable syntax:
//   - a variable that is unset OR set to the empty string means "use
//     the default";
//   - integers are parsed with strconv (no silent zeroing — the legacy
//     fmt.Sscanf parseInt is gone);
//   - SPLIT_ALLOW_WEAK_SECRET is parsed with strconv.ParseBool
//     (1/0/t/f/true/false/TRUE/False); any other value is a config error;
//   - addresses are host:port (empty host allowed for listeners, i.e.
//     ":9002"); IPv6 must use bracket syntax ("[::1]:9002").
//
// The shared-secret policy is Phase 6's mux.ValidateSecretMaterial,
// called here, not re-implemented; validation errors never include the
// secret value itself.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
)

const (
	RoleIran    = "iran"
	RoleGermany = "germany"
)

// Environment variable names (single source of truth).
const (
	EnvSocksListen = "SPLIT_SOCKS_LISTEN"             // Iran
	EnvWsListen    = "SPLIT_WS_LISTEN"                // Iran
	EnvDownCarrier = "SPLIT_DOWN_CARRIER_ADDR"        // Iran
	EnvUpWsUrl     = "SPLIT_UP_WS_URL"                // Germany
	EnvDownListen  = "SPLIT_DOWN_LISTEN"              // Germany
	EnvSecret      = "SPLIT_SECRET"                   // both
	EnvAllowWeak   = "SPLIT_ALLOW_WEAK_SECRET"        // both (bool)
	EnvMetricsPort = "SPLIT_METRICS_PORT"             // both
	EnvRelayBuf    = "SPLIT_RELAY_BUF"                // both
	EnvQueueBytes  = "SPLIT_STREAM_QUEUE_BYTES"       // both
	EnvQueueFrames = "SPLIT_STREAM_QUEUE_FRAMES"      // both
	EnvQueueTotal  = "SPLIT_STREAM_QUEUE_TOTAL_BYTES" // both
	EnvOverflowMs  = "SPLIT_STREAM_OVERFLOW_MS"       // both
)

// Defaults (mirror the pre-Phase-7 hardcoded values; every one is safe
// and bounded — the queue zeros fall back to mux.DefaultStreamLimits
// via mux.SanitizeLimits at runtime).
const (
	DefaultSocksListen = "127.0.0.1:10900"
	DefaultWsListen    = "127.0.0.1:9001"
	DefaultDownCarrier = "127.0.0.1:10802"
	// Placeholder URL: rejected by Validate so a fresh install fails
	// fast instead of dialing a dead domain forever.
	DefaultUpWsUrl    = "wss://cdn.example.com/upload"
	DefaultDownListen = ":9002"
	// Placeholder secret: rejected by the Phase 6 policy.
	DefaultSecret       = "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING"
	DefaultRelayBuf     = 32768
	DefaultKeepAlive    = 30 * time.Second
	ExpectedCarrierPath = "/upload" // the only path Iran's WS server serves

	// Relay buffer bounds: it is the socket read chunk size. 1 KiB
	// minimum keeps frame overhead sane; 8 MiB maximum stops a
	// misconfiguration from allocating absurd per-connection buffers.
	MinRelayBuf = 1024
	MaxRelayBuf = 8 << 20 // 8 MiB

	// Stream-queue bounds. Zero means "library default"; the maxima keep
	// a misconfigured deployment from reserving gigabytes.
	MaxQueueBytesPerStream = 64 << 20  // 64 MiB
	MaxQueueBytesTotal     = 256 << 20 // 256 MiB
	MaxOverflowWaitMs      = 30000     // 30 s

	MinPort = 1
	MaxPort = 65535
)

// Config is the full configuration for one splitter role. Role-irrelevant
// fields always carry their defaults; Validate(role) enforces only the
// role-relevant ones. Tests may construct Config directly and call
// Validate without touching the environment.
type Config struct {
	// Role-specific
	SocksListen     string // Iran: SOCKS5 listener (host:port)
	WsListen        string // Iran: up-carrier WS server (host:port)
	DownCarrierAddr string // Iran: down-carrier dial target (host:port)
	UpWsUrl         string // Germany: up-carrier WS URL (ws:// or wss://host/upload)
	DownListen      string // Germany: down-carrier TCP listener (host:port, host may be empty)

	// Shared
	Secret               string        // never logged, never echoed in errors
	AllowWeakSecret      bool          // SPLIT_ALLOW_WEAK_SECRET (Phase 6 bypass)
	MetricsPort          int           // 0 = metrics disabled; else 1..65535, binds 127.0.0.1
	RelayBufSize         int           // socket read chunk size
	KeepAliveInterval    time.Duration // fixed default; no env variable
	QueueBytesPerStream  int           // 0 = library default
	QueueFramesPerStream int           // 0 = library default (max mux.MaxFrames)
	QueueBytesTotal      int           // 0 = library default
	OverflowWaitMs       int           // 0 = library default
}

// Defaults returns a Config with all built-in defaults (no env read).
func Defaults() *Config {
	return &Config{
		SocksListen:       DefaultSocksListen,
		WsListen:          DefaultWsListen,
		DownCarrierAddr:   DefaultDownCarrier,
		UpWsUrl:           DefaultUpWsUrl,
		DownListen:        DefaultDownListen,
		Secret:            DefaultSecret,
		MetricsPort:       0,
		RelayBufSize:      DefaultRelayBuf,
		KeepAliveInterval: DefaultKeepAlive,
	}
}

// ConfigError aggregates every validation problem found, formatted as a
// bulleted list.
type ConfigError struct {
	Problems []string
}

func (e *ConfigError) Error() string {
	var b strings.Builder
	b.WriteString("configuration validation failed:")
	for _, p := range e.Problems {
		b.WriteString("\n  - " + p)
	}
	return b.String()
}

// Load reads the environment, applies defaults, parses and validates
// everything, and returns the complete configuration — or ALL problems
// at once. role must be RoleIran or RoleGermany.
func Load(role string) (*Config, error) {
	if role != RoleIran && role != RoleGermany {
		return nil, fmt.Errorf("config: unknown role %q (want %q or %q)", role, RoleIran, RoleGermany)
	}
	c := Defaults()
	var problems []string

	c.SocksListen = envString(EnvSocksListen, c.SocksListen)
	c.WsListen = envString(EnvWsListen, c.WsListen)
	c.DownCarrierAddr = envString(EnvDownCarrier, c.DownCarrierAddr)
	c.UpWsUrl = envString(EnvUpWsUrl, c.UpWsUrl)
	c.DownListen = envString(EnvDownListen, c.DownListen)
	c.Secret = envString(EnvSecret, c.Secret)
	c.MetricsPort = envInt(&problems, EnvMetricsPort, 0, 0, MaxPort)
	c.RelayBufSize = envInt(&problems, EnvRelayBuf, DefaultRelayBuf, MinRelayBuf, MaxRelayBuf)
	c.QueueBytesPerStream = envInt(&problems, EnvQueueBytes, 0, 0, MaxQueueBytesPerStream)
	c.QueueFramesPerStream = envInt(&problems, EnvQueueFrames, 0, 0, mux.MaxFrames)
	c.QueueBytesTotal = envInt(&problems, EnvQueueTotal, 0, 0, MaxQueueBytesTotal)
	c.OverflowWaitMs = envInt(&problems, EnvOverflowMs, 0, 0, MaxOverflowWaitMs)

	if v, ok := os.LookupEnv(EnvAllowWeak); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			problems = append(problems, fmt.Sprintf(
				"%s=%q: expected a boolean (true/false, 1/0)", EnvAllowWeak, v))
		} else {
			c.AllowWeakSecret = b
		}
	}

	if err := c.Validate(role); err != nil {
		var ce *ConfigError
		if errors.As(err, &ce) {
			problems = append(problems, ce.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return nil, &ConfigError{Problems: problems}
	}
	return c, nil
}

// Validate runs the pure validation rules for the given role and returns
// every problem at once (aggregated). It is exported so tests (and
// future non-env callers) can validate a directly-constructed Config
// without environment access. Zero-valued queue fields are the
// documented "library default" sentinel (mux.SanitizeLimits) and are
// therefore NOT errors; negative values are.
func (c *Config) Validate(role string) error {
	var problems []string

	switch role {
	case RoleIran:
		checkHostPort(&problems, EnvSocksListen, c.SocksListen, true)
		checkHostPort(&problems, EnvWsListen, c.WsListen, false)
		checkHostPort(&problems, EnvDownCarrier, c.DownCarrierAddr, true)
		if conflict(c.SocksListen, c.WsListen) {
			problems = append(problems, fmt.Sprintf(
				"%s and %s use the same endpoint %q; the app owns both listeners",
				EnvSocksListen, EnvWsListen, c.SocksListen))
		}
	case RoleGermany:
		checkWsUrl(&problems, c.UpWsUrl)
		checkHostPort(&problems, EnvDownListen, c.DownListen, false)
	case "":
		return fmt.Errorf("config: no role given")
	default:
		return fmt.Errorf("config: unknown role %q (want %q or %q)", role, RoleIran, RoleGermany)
	}
	// App-owned listener endpoints vs the metrics port (metrics always
	// binds 127.0.0.1:<port>): a collision would fail at bind time, so
	// report it at config time.
	if c.MetricsPort > 0 {
		metricsAddr := "127.0.0.1:" + strconv.Itoa(c.MetricsPort)
		for _, ep := range roleOwnedEndpoints(role, c) {
			if conflict(metricsAddr, ep[1]) {
				problems = append(problems, fmt.Sprintf(
					"%s=%d collides with %s=%q; both would bind the same endpoint",
					EnvMetricsPort, c.MetricsPort, ep[0], ep[1]))
			}
		}
	}

	// Shared numeric bounds (0 = library default where documented).
	if c.MetricsPort < 0 || c.MetricsPort > MaxPort {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected a port between 0 (disabled) and %d",
			EnvMetricsPort, c.MetricsPort, MaxPort))
	}
	if c.RelayBufSize < 0 || (c.RelayBufSize > 0 && c.RelayBufSize > MaxRelayBuf) {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected %d..%d bytes (0 = library default %d)",
			EnvRelayBuf, c.RelayBufSize, MinRelayBuf, MaxRelayBuf, DefaultRelayBuf))
	}
	if c.QueueBytesPerStream < 0 || c.QueueBytesPerStream > MaxQueueBytesPerStream {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueBytes, c.QueueBytesPerStream, MaxQueueBytesPerStream))
	}
	if c.QueueFramesPerStream < 0 || c.QueueFramesPerStream > mux.MaxFrames {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueFrames, c.QueueFramesPerStream, mux.MaxFrames))
	}
	if c.QueueBytesTotal < 0 || c.QueueBytesTotal > MaxQueueBytesTotal {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueTotal, c.QueueBytesTotal, MaxQueueBytesTotal))
	}
	if c.OverflowWaitMs < 0 || c.OverflowWaitMs > MaxOverflowWaitMs {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d milliseconds",
			EnvOverflowMs, c.OverflowWaitMs, MaxOverflowWaitMs))
	}
	// Cross-field: the carrier-wide budget must cover one stream's share.
	if c.QueueBytesPerStream > 0 && c.QueueBytesTotal > 0 &&
		c.QueueBytesTotal < c.QueueBytesPerStream {
		problems = append(problems, fmt.Sprintf(
			"%s=%d is smaller than %s=%d; the aggregate budget must cover at least one stream",
			EnvQueueTotal, c.QueueBytesTotal, EnvQueueBytes, c.QueueBytesPerStream))
	}

	// Secret policy: Phase 6's validator, not duplicated here. The
	// message never includes the secret value.
	if err := mux.ValidateSecretMaterial(c.Secret, c.AllowWeakSecret); err != nil {
		problems = append(problems, fmt.Sprintf(
			"%s: does not satisfy the minimum security requirements (%v); generate one with: openssl rand -hex 32",
			EnvSecret, err))
	}

	if len(problems) > 0 {
		return &ConfigError{Problems: problems}
	}
	return nil
}

// roleOwnedEndpoints lists this role's app-owned listener endpoints
// (the dial target is not a local listener, so it is excluded).
func roleOwnedEndpoints(role string, c *Config) [][2]string {
	if role == RoleIran {
		return [][2]string{
			{EnvSocksListen, c.SocksListen},
			{EnvWsListen, c.WsListen},
		}
	}
	return [][2]string{{EnvDownListen, c.DownListen}}
}

// checkHostPort validates a host:port endpoint. requireHost applies to
// dial targets (a listen address may omit the host: ":9002"). IPv6
// requires bracket syntax ("[::1]:9002") — that is standard
// net.SplitHostPort behavior.
func checkHostPort(problems *[]string, name, addr string, requireHost bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected host:port (e.g. 127.0.0.1:9001, :9002 or [::1]:9002)", name, addr))
		return
	}
	if requireHost && host == "" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: dial target requires an explicit host (e.g. 127.0.0.1:10802)", name, addr))
		return
	}
	if strings.ContainsAny(host, " \t\n") {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: host must not contain whitespace", name, addr))
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < MinPort || p > MaxPort {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected a port between %d and %d", name, addr, MinPort, MaxPort))
	}
}

// checkWsUrl validates the up-carrier WebSocket URL: ws:// or wss://
// scheme, non-empty host, and the carrier path the Iran side serves.
// Query strings are allowed (CDN dial patterns). The value is echoed in
// errors because a URL is not secret material.
func checkWsUrl(problems *[]string, raw string) {
	if raw == DefaultUpWsUrl {
		*problems = append(*problems, fmt.Sprintf(
			"%s is still the placeholder %q; set the real CDN up-carrier URL", EnvUpWsUrl, raw))
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: malformed URL: %v", EnvUpWsUrl, raw, err))
		return
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: scheme must be ws or wss (got %q)", EnvUpWsUrl, raw, u.Scheme))
		return
	}
	if u.Host == "" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: missing host", EnvUpWsUrl, raw))
		return
	}
	if u.Path != ExpectedCarrierPath {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: path must be %q (the only path the Iran side serves)", EnvUpWsUrl, raw, ExpectedCarrierPath))
	}
}

// conflict reports whether two app-owned listen endpoints would fight
// over the same bind address: equal ports AND either identical hosts or
// one of them binding all interfaces.
func conflict(a, b string) bool {
	ah, ap, aok := portOf(a)
	bh, bp, bok := portOf(b)
	if !aok || !bok || ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	return bindsEverything(ah) || bindsEverything(bh)
}

func bindsEverything(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

// portOf splits a host:port endpoint into (host, port, ok).
func portOf(addr string) (string, int, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

// envString returns the env value, or def when the variable is unset or
// the empty string (documented: empty = use the default).
func envString(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// envInt parses an integer env variable with explicit min/max bounds and
// aggregates a precise error (never a silent zero). Unset/empty returns
// def.
func envInt(problems *[]string, name string, def, min, max int) int {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected an integer between %d and %d", name, v, min, max))
		return def
	}
	if n < min || n > max {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected an integer between %d and %d", name, v, min, max))
		return def
	}
	return n
}
