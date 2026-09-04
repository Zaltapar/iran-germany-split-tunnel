// Tests for the Phase 7 centralized configuration layer.
//
// Two levels:
//   - pure validation (Validate + unexported helpers): directly
//     constructed Config values, no environment access;
//   - full Load path: env parsing, defaults, error aggregation and the
//     Phase 6 secret-policy wiring (t.Setenv isolation per test).
package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
)

// strongSecret is a 64-hex-char value: long enough and not a known
// placeholder, so the Phase 6 policy accepts it.
const strongSecret = "0f3a9c2e8b7d4156a9e0c2b7d3f4a8c1e5b6d7a8f9c0e1b2d3a4f5c6b7e8d9a0"

// isolatedEnv pins every handled variable to the empty string (= "use
// the default") so ambient host values can't leak into the tests.
// t.Setenv restores the previous state when each test finishes.
func isolatedEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvSocksListen, EnvWsListen, EnvDownCarrier, EnvUpWsUrl, EnvDownListen,
		EnvSecret, EnvAllowWeak, EnvMetricsPort, EnvRelayBuf,
		EnvQueueBytes, EnvQueueFrames, EnvQueueTotal, EnvOverflowMs,
		EnvSessionBufTotal,
		EnvBootstrapWait,
	} {
		t.Setenv(name, "")
	}
}

func problemsOf(t *testing.T, err error) []string {
	t.Helper()
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConfigError, got %T (%v)", err, err)
	}
	return ce.Problems
}

func joinedProblems(p []string) string { return strings.Join(p, "\n") }

func validIran() *Config {
	c := Defaults()
	c.Secret = strongSecret
	return c
}

func validGermany() *Config {
	c := validIran()
	c.UpWsUrl = "wss://cdn.example.org/upload"
	return c
}

func TestDefaults(t *testing.T) {
	c := Defaults()
	if c.SocksListen != DefaultSocksListen || c.WsListen != DefaultWsListen ||
		c.DownCarrierAddr != DefaultDownCarrier || c.UpWsUrl != DefaultUpWsUrl ||
		c.DownListen != DefaultDownListen || c.Secret != DefaultSecret {
		t.Fatalf("string defaults drifted: %+v", c)
	}
	if c.MetricsPort != 0 || c.RelayBufSize != DefaultRelayBuf ||
		c.KeepAliveInterval != DefaultKeepAlive {
		t.Fatalf("shared defaults drifted: %+v", c)
	}
	if c.KeepAliveInterval != 30*time.Second {
		t.Fatalf("DefaultKeepAlive drifted from 30s: %v", c.KeepAliveInterval)
	}
	// Zero = "library default" sentinel; the runtime fills it in via
	// mux.SanitizeLimits, so the config layer must ship zeros.
	if c.QueueBytesPerStream != 0 || c.QueueFramesPerStream != 0 ||
		c.QueueBytesTotal != 0 || c.OverflowWaitMs != 0 {
		t.Fatalf("queue fields must default to 0: %+v", c)
	}
	// Issue #6: the aggregate session-buffer budget also uses the
	// 0 = library default sentinel (node lifts it in Sanitize).
	if c.SessionBufTotal != 0 {
		t.Fatalf("SessionBufTotal must default to 0 (library default sentinel): %+v", c)
	}
	// Issue #7: the bootstrap wait uses the same 0 = library default
	// sentinel (node lifts it in Sanitize).
	if c.BootstrapWaitMs != 0 {
		t.Fatalf("BootstrapWaitMs must default to 0 (library default sentinel): %+v", c)
	}
}

func TestValidateRoleSpecificIran(t *testing.T) {
	if err := validIran().Validate(RoleIran); err != nil {
		t.Fatalf("valid Iran config rejected: %v", err)
	}
	// Germany-only fields are ignored for the Iran role.
	c := validIran()
	c.UpWsUrl = "ftp://example.com/wrong"
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("Iran role must ignore Germany-only fields: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"socks no port", func(c *Config) { c.SocksListen = "127.0.0.1" }, "host:port"},
		{"socks port 0", func(c *Config) { c.SocksListen = "127.0.0.1:0" }, "between 1 and 65535"},
		{"socks port too big", func(c *Config) { c.SocksListen = "127.0.0.1:70000" }, "between 1 and 65535"},
		{"socks bad port", func(c *Config) { c.SocksListen = "127.0.0.1:abc" }, "between 1 and 65535"},
		{"dial target empty host", func(c *Config) { c.DownCarrierAddr = ":10802" }, "explicit host"},
		{"unbracketed ipv6", func(c *Config) { c.WsListen = "::1:9001" }, "host:port"},
		{"too many colons", func(c *Config) { c.WsListen = "127.0.0.1:9001:22" }, "host:port"},
		{"whitespace host", func(c *Config) { c.WsListen = " 127.0.0.1:9001" }, "whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validIran()
			tc.mutate(c)
			ps := problemsOf(t, c.Validate(RoleIran))
			if !strings.Contains(joinedProblems(ps), tc.wantSub) {
				t.Fatalf("want problem containing %q, got: %v", tc.wantSub, ps)
			}
		})
	}

	// All valid listen forms (incl. wildcard host, bracketed IPv6 and
	// the bare ":port" listener form).
	for _, addr := range []string{"127.0.0.1:9001", "0.0.0.0:9001", "[::1]:9001", ":9001"} {
		c := validIran()
		c.WsListen = addr
		if err := c.Validate(RoleIran); err != nil {
			t.Fatalf("WsListen=%q should be valid: %v", addr, err)
		}
	}
}
func TestValidateRoleSpecificGermany(t *testing.T) {
	if err := validGermany().Validate(RoleGermany); err != nil {
		t.Fatalf("valid Germany config rejected: %v", err)
	}
	// Iran-only fields are ignored for the Germany role.
	c := validGermany()
	c.SocksListen = "garbage-no-port"
	if err := c.Validate(RoleGermany); err != nil {
		t.Fatalf("Germany role must ignore Iran-only fields: %v", err)
	}

	cases := []struct {
		name    string
		url     string
		wantSub string
	}{
		{"placeholder", DefaultUpWsUrl, "placeholder"},
		{"bad scheme", "http://cdn.example.org/upload", "scheme"},
		{"missing host", "wss:///upload", "missing host"},
		{"wrong path", "wss://cdn.example.org/other", "path"},
		{"not a url", "cdn.example.org", "scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validGermany()
			c.UpWsUrl = tc.url
			ps := problemsOf(t, c.Validate(RoleGermany))
			if !strings.Contains(joinedProblems(ps), tc.wantSub) {
				t.Fatalf("want problem containing %q, got: %v", tc.wantSub, ps)
			}
		})
	}

	// Valid forms: wss, plain ws on a LAN address, and a CDN query string.
	for _, raw := range []string{
		"wss://cdn.example.org/upload",
		"ws://10.0.0.5:9001/upload",
		"wss://cdn.example.org/upload?sig=abc",
	} {
		c := validGermany()
		c.UpWsUrl = raw
		if err := c.Validate(RoleGermany); err != nil {
			t.Fatalf("UpWsUrl=%q should be valid: %v", raw, err)
		}
	}

	// DownListen: bare ":9002" is fine, a missing port is not.
	c = validGermany()
	c.DownListen = "127.0.0.1"
	ps := problemsOf(t, c.Validate(RoleGermany))
	if !strings.Contains(joinedProblems(ps), "SPLIT_DOWN_LISTEN") {
		t.Fatalf("want SPLIT_DOWN_LISTEN problem, got: %v", ps)
	}
}

func TestCrossFieldConflicts(t *testing.T) {
	// Iran: socks and ws listener on the same endpoint.
	c := validIran()
	c.SocksListen = c.WsListen
	ps := problemsOf(t, c.Validate(RoleIran))
	if !strings.Contains(joinedProblems(ps), "same endpoint") {
		t.Fatalf("want same-endpoint problem, got: %v", ps)
	}

	// Iran: metrics port collides with the WS listener (wildcard bind).
	c = validIran()
	c.WsListen = "0.0.0.0:9001"
	c.MetricsPort = 9001
	ps = problemsOf(t, c.Validate(RoleIran))
	if !strings.Contains(joinedProblems(ps), "collides") {
		t.Fatalf("want metrics-collision problem, got: %v", ps)
	}

	// Same port, different concrete host, no wildcard: no collision.
	c = validIran()
	c.WsListen = "10.0.0.5:9001"
	c.MetricsPort = 9001
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("no collision expected: %v", err)
	}

	// Germany: metrics port collides with the down listener.
	c = validGermany()
	c.DownListen = ":9002"
	c.MetricsPort = 9002
	ps = problemsOf(t, c.Validate(RoleGermany))
	if !strings.Contains(joinedProblems(ps), "collides") {
		t.Fatalf("want metrics-collision problem, got: %v", ps)
	}
}

func TestQueueFields(t *testing.T) {
	// Zero = library default: valid.
	if err := validIran().Validate(RoleIran); err != nil {
		t.Fatalf("zero queue fields must be valid: %v", err)
	}

	// Explicit, consistent values: valid.
	c := validIran()
	c.QueueBytesPerStream = 1 << 20
	c.QueueBytesTotal = 8 << 20
	c.QueueFramesPerStream = mux.MaxFrames // upper bound is valid
	c.OverflowWaitMs = 500
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("consistent queue fields must be valid: %v", err)
	}

	// Aggregate budget smaller than one stream's share: error.
	c = validIran()
	c.QueueBytesPerStream = 4 << 20
	c.QueueBytesTotal = 2 << 20
	ps := problemsOf(t, c.Validate(RoleIran))
	if !strings.Contains(joinedProblems(ps), "aggregate budget") {
		t.Fatalf("want cross-field queue problem, got: %v", ps)
	}

	// Negative / out-of-range values constructed directly: errors.
	neg := validIran()
	neg.QueueBytesPerStream = -1
	ovf := validIran()
	ovf.OverflowWaitMs = 1 << 30
	badFrames := validIran()
	badFrames.QueueFramesPerStream = 1 << 30
	for name, cfg := range map[string]*Config{
		"negative bytes per stream":  neg,
		"overflow wait out of range": ovf,
		"frames out of range":        badFrames,
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(RoleIran); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

// TestSessionBufTotal (Issue #6): the node-level aggregate session-buffer
// budget — parse, bounds, and the 0-sentinel behavior, matching the
// existing queue-field patterns.
func TestSessionBufTotal(t *testing.T) {
	// 0 = library default: valid.
	if err := validIran().Validate(RoleIran); err != nil {
		t.Fatalf("zero SessionBufTotal must be valid: %v", err)
	}

	// Explicit values within bounds: valid (including the max).
	for _, v := range []int{1 << 20, MaxSessionBufTotal} {
		c := validIran()
		c.SessionBufTotal = v
		if err := c.Validate(RoleIran); err != nil {
			t.Fatalf("SessionBufTotal=%d must be valid: %v", v, err)
		}
	}

	// Out-of-range values: errors naming the variable.
	cases := []struct {
		name string
		v    int
	}{
		{"negative", -1},
		{"over max", MaxSessionBufTotal + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validIran()
			c.SessionBufTotal = tc.v
			ps := problemsOf(t, c.Validate(RoleIran))
			if !strings.Contains(joinedProblems(ps), EnvSessionBufTotal) {
				t.Fatalf("want problem naming %s, got: %v", EnvSessionBufTotal, ps)
			}
		})
	}

	// Load path: env parsing.
	isolatedEnv(t)
	t.Setenv(EnvSecret, strongSecret)
	t.Setenv(EnvSessionBufTotal, "67108864") // 64 MiB
	cfg, err := Load(RoleIran)
	if err != nil {
		t.Fatalf("Load with %s=67108864: %v", EnvSessionBufTotal, err)
	}
	if cfg.SessionBufTotal != 67108864 {
		t.Fatalf("SessionBufTotal = %d, want 67108864", cfg.SessionBufTotal)
	}

	// Load path: out-of-range env value is a parse/validation problem.
	t.Setenv(EnvSessionBufTotal, "999999999999")
	if _, err := Load(RoleIran); err == nil {
		t.Fatalf("Load with %s=999999999999 must fail", EnvSessionBufTotal)
	}
}

// TestBootstrapWait (Issue #7): the bounded bootstrap wait — parse,
// bounds, and the 0-sentinel behavior, matching the existing envInt
// patterns.
func TestBootstrapWait(t *testing.T) {
	// 0 = library default: valid.
	if err := validIran().Validate(RoleIran); err != nil {
		t.Fatalf("zero BootstrapWaitMs must be valid: %v", err)
	}

	// Explicit values within bounds: valid (including the max).
	for _, v := range []int{MinBootstrapWaitMs, 30000, MaxBootstrapWaitMs} {
		c := validIran()
		c.BootstrapWaitMs = v
		if err := c.Validate(RoleIran); err != nil {
			t.Fatalf("BootstrapWaitMs=%d must be valid: %v", v, err)
		}
	}

	// Out-of-range values: errors naming the variable.
	for _, v := range []int{499, MaxBootstrapWaitMs + 1} {
		c := validIran()
		c.BootstrapWaitMs = v
		ps := problemsOf(t, c.Validate(RoleIran))
		if !strings.Contains(joinedProblems(ps), EnvBootstrapWait) {
			t.Fatalf("want problem naming %s for %d, got: %v", EnvBootstrapWait, v, ps)
		}
	}

	// Load path: env parsing.
	isolatedEnv(t)
	t.Setenv(EnvSecret, strongSecret)
	t.Setenv(EnvBootstrapWait, "45000")
	cfg, err := Load(RoleIran)
	if err != nil {
		t.Fatalf("Load with %s=45000: %v", EnvBootstrapWait, err)
	}
	if cfg.BootstrapWaitMs != 45000 {
		t.Fatalf("BootstrapWaitMs = %d, want 45000", cfg.BootstrapWaitMs)
	}

	// Load path: out-of-range env value is a parse/validation problem.
	t.Setenv(EnvBootstrapWait, "999999999")
	if _, err := Load(RoleIran); err == nil {
		t.Fatalf("Load with %s=999999999 must fail", EnvBootstrapWait)
	}
}

func TestUnknownRole(t *testing.T) {
	// Unknown/empty roles are plain errors, not aggregated ConfigErrors.
	if err := validIran().Validate("france"); err == nil ||
		strings.Contains(err.Error(), "configuration validation failed") {
		t.Fatalf("unknown role must be a plain error, got: %v", err)
	}
	if err := validIran().Validate(""); err == nil {
		t.Fatal("empty role must fail")
	}
	if _, err := Load("france"); err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("Load(unknown role) must fail: %v", err)
	}
}

func TestSecretPolicyNeverLeaksValue(t *testing.T) {
	c := validIran()
	// 30 chars, not on the blocklist: fails only the length policy.
	c.Secret = "weak-secret-for-testing-only-1"
	err := c.Validate(RoleIran)
	ps := problemsOf(t, err)
	joined := joinedProblems(ps)
	if !strings.Contains(joined, "SPLIT_SECRET") {
		t.Fatalf("want SPLIT_SECRET problem, got: %v", ps)
	}
	if strings.Contains(joined, c.Secret) {
		t.Fatalf("error text leaked the secret value: %v", ps)
	}
	if !strings.Contains(err.Error(), "openssl rand -hex 32") {
		t.Fatalf("secret error should hint at generation: %v", err)
	}
}

// Validate must be usable without any environment access (direct
// construction path, e.g. future non-env callers and tests).
func TestValidateDoesNotReadEnv(t *testing.T) {
	isolatedEnv(t) // ambient env provably irrelevant
	c := &Config{
		SocksListen:     "127.0.0.1:10900",
		WsListen:        "127.0.0.1:9001",
		DownCarrierAddr: "127.0.0.1:10802",
		Secret:          strongSecret,
		// Phase 5 carrier-loss recovery bounds (must be in range for
		// Validate; take the canonical defaults).
		CarrierGraceMs:  Defaults().CarrierGraceMs,
		SessionBufBytes: Defaults().SessionBufBytes,
	}
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("hand-built config must validate without env: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Full Load path (environment)
// ---------------------------------------------------------------------------

func TestLoadValidIran(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, strongSecret)
	cfg, err := Load(RoleIran)
	if err != nil {
		t.Fatalf("valid Iran load failed: %v", err)
	}
	if cfg.SocksListen != DefaultSocksListen || cfg.WsListen != DefaultWsListen ||
		cfg.DownCarrierAddr != DefaultDownCarrier || cfg.RelayBufSize != DefaultRelayBuf ||
		cfg.MetricsPort != 0 || cfg.Secret != strongSecret {
		t.Fatalf("unexpected loaded config: %+v", cfg)
	}
}

func TestLoadValidGermanyWithEnv(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, strongSecret)
	t.Setenv(EnvUpWsUrl, "wss://my-cdn.example/upload")
	t.Setenv(EnvDownListen, "127.0.0.1:9443")
	t.Setenv(EnvMetricsPort, "9494")
	t.Setenv(EnvRelayBuf, "65536")
	cfg, err := Load(RoleGermany)
	if err != nil {
		t.Fatalf("valid Germany load failed: %v", err)
	}
	if cfg.UpWsUrl != "wss://my-cdn.example/upload" || cfg.DownListen != "127.0.0.1:9443" ||
		cfg.MetricsPort != 9494 || cfg.RelayBufSize != 65536 {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}
}

func TestLoadPlaceholderSecretRejected(t *testing.T) {
	isolatedEnv(t) // secret stays the CHANGE-ME placeholder
	_, err := Load(RoleIran)
	ps := problemsOf(t, err)
	if !strings.Contains(joinedProblems(ps), "SPLIT_SECRET") {
		t.Fatalf("placeholder secret must be rejected: %v", ps)
	}
}

func TestLoadBlockedSecretRejected(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, "password")
	_, err := Load(RoleIran)
	if err == nil {
		t.Fatal("blocklisted secret must be rejected")
	}
}

func TestLoadWeakSecretBypass(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, "short") // < 32 chars, not blocklisted

	t.Setenv(EnvAllowWeak, "1")
	cfg, err := Load(RoleIran)
	if err != nil {
		t.Fatalf("bypassed weak secret must load: %v", err)
	}
	if !cfg.AllowWeakSecret {
		t.Fatal("AllowWeakSecret must be true")
	}

	t.Setenv(EnvAllowWeak, "true")
	if _, err := Load(RoleIran); err != nil {
		t.Fatalf("bypass 'true' must load: %v", err)
	}

	t.Setenv(EnvAllowWeak, "0")
	if _, err := Load(RoleIran); err == nil {
		t.Fatal("short secret without bypass must be rejected")
	}
}

func TestLoadInvalidAllowWeakBool(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, strongSecret)
	t.Setenv(EnvAllowWeak, "yes-please")
	_, err := Load(RoleIran)
	ps := problemsOf(t, err)
	if !strings.Contains(joinedProblems(ps), "SPLIT_ALLOW_WEAK_SECRET") {
		t.Fatalf("want bool problem, got: %v", ps)
	}
}
func TestLoadIntErrors(t *testing.T) {
	for _, tc := range []struct {
		env   string
		value string
		name  string
	}{
		{EnvRelayBuf, "abc", "relay non-numeric"},
		{EnvRelayBuf, "100", "relay below min"},
		{EnvRelayBuf, "99999999", "relay above max"},
		{EnvMetricsPort, "abc", "metrics non-numeric"},
		{EnvMetricsPort, "70000", "metrics out of range"},
		{EnvOverflowMs, "-1", "overflow wait negative"},
		{EnvQueueTotal, "99999999999999999999", "queue total overflow"},
		{EnvQueueFrames, "999999999999", "frames out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedEnv(t)
			t.Setenv(EnvSecret, strongSecret)
			t.Setenv(tc.env, tc.value)
			_, err := Load(RoleIran)
			joined := joinedProblems(problemsOf(t, err))
			if !strings.Contains(joined, tc.env) ||
				!strings.Contains(joined, "expected an integer") {
				t.Fatalf("want precise %s problem, got: %s", tc.env, joined)
			}
		})
	}
}

func TestLoadAggregatesAllProblems(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvSecret, "short")      // secret policy problem
	t.Setenv(EnvRelayBuf, "abc")      // int problem
	t.Setenv(EnvMetricsPort, "70000") // int problem
	t.Setenv(EnvWsListen, "noport")   // address problem
	_, err := Load(RoleIran)
	ps := problemsOf(t, err)
	joined := joinedProblems(ps)
	for _, want := range []string{EnvSecret, EnvRelayBuf, EnvMetricsPort, EnvWsListen} {
		if !strings.Contains(joined, want) {
			t.Fatalf("aggregated error must name %s; got: %v", want, ps)
		}
	}
	if len(ps) < 4 {
		t.Fatalf("want >=4 problems, got %d: %v", len(ps), ps)
	}
	if !strings.HasPrefix(err.Error(), "configuration validation failed:") {
		t.Fatalf("unexpected error format: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Unexported helper units
// ---------------------------------------------------------------------------

func TestEnvIntDirect(t *testing.T) {
	const name = "SPLIT_TEST_UNSET_INT"
	var problems []string

	if got := envInt(&problems, name, 42, 0, 100); got != 42 || len(problems) != 0 {
		t.Fatalf("unset env must return default, got %d, %v", got, problems)
	}
	t.Setenv(name, "")
	if got := envInt(&problems, name, 42, 0, 100); got != 42 || len(problems) != 0 {
		t.Fatalf("empty env must return default, got %d, %v", got, problems)
	}
	// Zero is a REAL value when the range allows it (queue sentinels).
	t.Setenv(name, "0")
	if got := envInt(&problems, name, 42, 0, 100); got != 0 || len(problems) != 0 {
		t.Fatalf("zero in range must parse to 0, got %d, %v", got, problems)
	}
	// Out of range: default + a problem that quotes the offending value.
	t.Setenv(name, "101")
	if got := envInt(&problems, name, 42, 0, 100); got != 42 || len(problems) != 1 {
		t.Fatalf("out-of-range must return default + one problem, got %d, %v", got, problems)
	}
	if !strings.Contains(problems[0], "SPLIT_TEST_UNSET_INT=\"101\"") {
		t.Fatalf("problem must quote the offending value: %v", problems[0])
	}
}

func TestEnvString(t *testing.T) {
	const name = "SPLIT_TEST_UNSET_STR"
	if got := envString(name, "def"); got != "def" {
		t.Fatalf("unset must default: %q", got)
	}
	t.Setenv(name, "")
	if got := envString(name, "def"); got != "def" {
		t.Fatalf("empty must default: %q", got)
	}
	t.Setenv(name, "val")
	if got := envString(name, "def"); got != "val" {
		t.Fatalf("set value must win: %q", got)
	}
}

func TestConflict(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"127.0.0.1:9001", "127.0.0.1:9001", true},
		{"127.0.0.1:9001", "127.0.0.1:9002", false},
		{"0.0.0.0:9001", "127.0.0.1:9001", true},
		{"127.0.0.1:9001", "0.0.0.0:9001", true},
		{":9001", "127.0.0.1:9001", true},
		{"10.0.0.1:9001", "10.0.0.2:9001", false},
		{"not-a-port", "127.0.0.1:9001", false},
	} {
		if got := conflict(tc.a, tc.b); got != tc.want {
			t.Errorf("conflict(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
