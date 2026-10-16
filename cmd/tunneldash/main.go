// Command tunneldash is the monitoring dashboard for the Iran–Germany
// split-tunnel deployment.
//
// Safe defaults (local build):
//   - Binds to 127.0.0.1:8080 (loopback only)
//   - Read-only: mutations are disabled and the apply endpoint always
//     returns 403
//   - Fixture data by default: no production hosts are contacted
//   - No secrets are ever displayed
//
// Server-hosted TLS build (one-click dashboard on Germany, design §3):
// when the config carries a complete TLS section (tls.enabled, certFile,
// keyFile, 32-hex basePath) the dashboard binds over TLS on its own
// dedicated port (never 443, which Xray Reality owns), mounts the whole
// surface under the random basePath, serves security headers, and requires
// browser-native HTTP Basic auth via a salted PBKDF2-HMAC-SHA256 verifier
// file (SPLIT_TUNNELDASH_CREDENTIALS). The deprecated admin Bearer token
// (SPLIT_TUNNELDASH_TOKEN / SPLIT_TUNNELDASH_TOKEN_FILE) remains as a
// fallback for in-flight host builds. Non-loopback binds are refused unless
// the TLS config is complete (fail closed).
//
// Usage:
//
//	tunneldash                          # fixture mode, default config
//	tunneldash -config my-config.json   # use a custom config file
//	tunneldash -listen 127.0.0.1:9090   # override the listen address
//	tunneldash -help                    # print full flag help
//
// This command does NOT contact, modify, or deploy to any production host.
// It does NOT call Arvan APIs. With a fixture/http/ssh config it may read
// remote metrics/logs over the strict pinned SSH collector only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/dashboard"
)

// buildInfo is stamped at build time by the reproducible build script
// (scripts/build-linux.sh) via -ldflags "-X main.buildInfo=<git-commit>". It is
// empty in local/dev builds. It carries only a non-secret build identity.
var buildInfo = ""

func main() {
	var (
		configPath string
		listenAddr string
		forceRO    bool
		forceFix   bool
		validate   bool
		version    bool
	)

	fs := flag.NewFlagSet("tunneldash", flag.ExitOnError)
	fs.StringVar(&configPath, "config", "", "Path to a dashboard config JSON file (default: built-in fixture config)")
	fs.StringVar(&listenAddr, "listen", "", "Override the listen address (loopback unless the config's TLS section is complete)")
	fs.BoolVar(&forceRO, "read-only", false, "Force read-only mode (apply endpoint always returns 403)")
	fs.BoolVar(&forceFix, "fixture", false, "Force fixture data source for all servers (no external host access)")
	fs.BoolVar(&validate, "validate-config", false, "Validate the config and exit (0 = valid); no listener is started")
	fs.BoolVar(&version, "version", false, "Print the reproducible-build commit stamp and exit (scripts/build-linux.sh embeds it via -X main.buildInfo)")
	fs.Usage = func() {
		out := os.Stderr
		out.WriteString("Usage: tunneldash [options]\n\n")
		out.WriteString("Monitoring dashboard for the Iran–Germany split-tunnel.\n")
		out.WriteString("Safe defaults: binds to 127.0.0.1, read-only, no host access.\n")
		out.WriteString("With a complete TLS config section it may bind a public port over TLS,\n")
		out.WriteString("mounted under a random 32-hex basePath, with security headers and\n")
		out.WriteString("browser-native HTTP Basic auth (SPLIT_TUNNELDASH_CREDENTIALS).\n\n")
		out.WriteString("Options:\n")
		fs.PrintDefaults()
		out.WriteString("\nEnvironment variables:\n")
		out.WriteString("  DASHBOARD_LISTEN               Override listen address (same as -listen)\n")
		out.WriteString("  DASHBOARD_CONFIG               Config file path (same as -config)\n")
		out.WriteString("  DASHBOARD_READONLY             Set to 'false' to disable read-only (requires a real mutator)\n")
		out.WriteString("  SPLIT_TUNNELDASH_CREDENTIALS  Path to a 0640 PBKDF2 verifier file (HTTP Basic auth; value never logged)\n")
		out.WriteString("  SPLIT_TUNNELDASH_TOKEN        [deprecated] Admin Bearer token (fallback; never logged)\n")
		out.WriteString("  SPLIT_TUNNELDASH_TOKEN_FILE   [deprecated] Path to a 0600 file holding the admin Bearer token\n")
	}
	fs.Parse(os.Args[1:])

	// -version: print the reproducible-build commit stamp and exit.
	if version {
		commit := buildInfo
		if commit == "" {
			commit = "dev"
		}
		fmt.Println("tunneldash buildInfo:", commit)
		return
	}

	// Load config.
	cfg := dashboard.DefaultConfig()
	if configPath != "" || os.Getenv("DASHBOARD_CONFIG") != "" {
		path := configPath
		if path == "" {
			path = os.Getenv("DASHBOARD_CONFIG")
		}
		loaded, err := dashboard.LoadConfig(path)
		if err != nil {
			log.Fatalf("tunneldash: %v", err)
		}
		cfg = loaded
	}

	// Apply flag overrides.
	if listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}
	if envAddr := os.Getenv("DASHBOARD_LISTEN"); envAddr != "" {
		cfg.ListenAddr = envAddr
	}
	if forceRO {
		cfg.ReadOnly = true
	}
	if envRO := os.Getenv("DASHBOARD_READONLY"); envRO == "false" {
		cfg.ReadOnly = false
	}
	if forceFix {
		for i := range cfg.Servers {
			cfg.Servers[i].SourceType = "fixture"
		}
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("tunneldash: config validation: %v", err)
	}

	// --validate-config: exit after a successful validation (used by the
	// installer preflight to prove the generated dashboard config loads).
	if validate {
		log.Println("tunneldash: config is valid")
		return
	}

	// Build the dashboard components.
	cache := dashboard.NewCache(cfg)
	audit := dashboard.NewAuditLog(cfg.MaxAudit)

	tlsMode := cfg.TLS != nil && cfg.TLS.Enabled

	// Resolve a usable authenticator. In tlsMode at least one credential
	// source MUST be loadable — a public TLS listener that has no auth
	// mechanism is refused to start (fail-closed). In loopback mode (plain
	// HTTP on 127.0.0.1) the loopback default is safe. See
	// resolveAuthenticator for the Basic-auth vs deprecated-Bearer ordering.
	auth, err := resolveAuthenticator()
	if err != nil {
		if tlsMode {
			// TLS build: fail closed on any unauthenticated state.
			log.Fatalf("tunneldash: %v", err)
		}
		// Non-TLS loopback build: log the misconfiguration and fall back to
		// loopback auth (the listener itself still refuses non-loopback
		// binds, so the "safe" default is preserved).
		log.Printf("tunneldash: %v; falling back to loopback authenticator (listener still binds loopback-only)", err)
		auth = dashboard.NewLoopbackAuthenticator()
	}
	// nil mutator = safe default (apply endpoint always refuses).

	server := dashboard.NewTLSServer(cfg, cache, audit, nil, auth)

	// Wire the C2/C3/C4 control agent from config.
	//
	// - No control section (cfg.Control == nil): c2Agent stays nil; all
	//   forwarding endpoints return 503 agent_unavailable (exactly the
	//   today behaviour — read-only dashboard is fully functional).
	// - Control section with socketPath set: attach a ControlClient. The
	//   client itself does not dial at construction time; each Call dials
	//   the socket. If the socket is absent at request time the endpoint
	//   answers 503 agent_unavailable (no crash).
	// - applyEnabled=true + empty socketPath is already refused by
	//   cfg.Validate() above (fail closed), so we only reach here with a
	//   valid config.
	if cfg.Control != nil && cfg.Control.SocketPath != "" {
		server.SetControlAgent(dashboard.NewControlClient(cfg.Control.SocketPath))
		log.Printf("tunneldash: control agent wired to %s (applyEnabled=%v, c3Flags/c4Flags from config)",
			cfg.Control.SocketPath, cfg.Control.ApplyEnabled)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		log.Printf("tunneldash: received %v, shutting down", s)
		cancel()
	}()

	if tlsMode {
		bp := cfg.BasePath()
		log.Printf("tunneldash: listening over TLS on %s (read-only=%v, basePath=%s, servers=%d)",
			cfg.ListenAddr, cfg.ReadOnly, bp, len(cfg.Servers))
		log.Printf("tunneldash: UI at https://<host>:<port>%s  —  API at https://<host>:<port>%sapi/v1/", bp, bp)
		switch auth.Name() {
		case "basic":
			log.Println("tunneldash: HTTP Basic auth is active (PBKDF2 verifier; username + password never logged)")
		case "bearer":
			log.Println("tunneldash: deprecated admin Bearer token is active (value never logged)")
		}
		// The bind gate is relaxed ONLY because the TLS config is complete
		// (validateListenAddrSecure); otherwise a public bind is refused.
		log.Printf("tunneldash: NOTE: server-hosted TLS build. The dashboard binds a public port ONLY because a complete TLS config (cert+key+basePath) is set.")
		if err := server.ListenAndServeTLS(ctx); err != nil {
			log.Fatalf("tunneldash: %v", err)
		}
		return
	}

	log.Printf("tunneldash: listening on %s (read-only=%v, servers=%d)",
		cfg.ListenAddr, cfg.ReadOnly, len(cfg.Servers))
	log.Printf("tunneldash: UI at http://%s/  —  API at http://%s/api/v1/", cfg.ListenAddr, cfg.ListenAddr)
	log.Printf("tunneldash: NOTE: this is a local dashboard. No production hosts are contacted unless a server source type is http/ssh.")

	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("tunneldash: %v", err)
	}
}

// resolveAuthenticator selects the dashboard Authenticator. Preferred: a
// Basic-auth PBKDF2 verifier file (SPLIT_TUNNELDASH_CREDENTIALS). Legacy
// fallback: the deprecated Bearer token (SPLIT_TUNNELDASH_TOKEN / _FILE).
// Returns (auth, nil) on success, or (nil, err) describing the
// misconfiguration. The caller owns the fail-closed decision: a TLS build
// must refuse to start when no credential source is loadable, while a
// loopback build may fall back to the loopback authenticator.
func resolveAuthenticator() (dashboard.Authenticator, error) {
	if basic, _ := dashboard.LoadBasicAuthenticatorFromEnvErr(); basic != nil {
		return basic, nil
	}
	if tok := dashboard.LoadAdminToken(); tok != "" {
		log.Println("tunneldash: WARNING: using deprecated admin Bearer token; run `splitterctl rotate-dashboard-credentials` to move to HTTP Basic auth (username/password)")
		return dashboard.NewBearerTokenAuthenticator(tok), nil
	}
	if dashboard.DashCredentialsConfigured() {
		// Propagate the bounded parse/read detail (field + cause, never the
		// verifier contents or a password) so the operator gets a diagnosable
		// message instead of a generic "could not be loaded".
		_, verr := dashboard.LoadBasicAuthenticatorFromEnvErr()
		if verr != nil {
			return nil, fmt.Errorf("a Basic-auth credential file (%s) is configured but could not be loaded: %v; refusing to start unauthenticated", dashboard.EnvDashCredentials, verr)
		}
		return nil, fmt.Errorf("a Basic-auth credential file (%s) is configured but could not be loaded or parsed (unreadable, empty, or not a valid PBKDF2 verifier); refusing to start unauthenticated", dashboard.EnvDashCredentials)
	}
	if dashboard.AdminTokenConfigured() {
		return nil, fmt.Errorf("a deprecated Bearer-token source is configured but could not be loaded; refusing to start unauthenticated (check %s / %s, or migrate to Basic auth)", dashboard.EnvAdminToken, dashboard.EnvAdminTokenFile)
	}
	// No credential source at all. Safe for loopback; a misconfiguration
	// for a TLS build (the caller detects tlsMode).
	return nil, fmt.Errorf("no dashboard credential source configured (%s or %s unset)", dashboard.EnvDashCredentials, dashboard.EnvAdminToken)
}
