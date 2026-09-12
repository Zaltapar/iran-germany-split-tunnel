// Command splitterctl is the thin operator-facing deployment entrypoint.
// Deployment policy and state live in internal/deploy; this file only parses
// commands, maps the operator environment to a deploy.InstallRequest,
// renders safe output, and maps errors to exit status.
//
// Mutation commands (install, rollback, uninstall, recover) always operate
// on the canonical production state root (systemd.StateDir) and require the
// Linux target platform; privilege and host gates live in the T5/T6 packages
// they delegate to (root-checked, no shell). Read-only commands (status,
// doctor, config show) honor SPLITTERCTL_STATE_ROOT.
//
// Mutation environment contract (errors name fields, never values — the
// secret and Reality key material are never echoed):
//
//	SPLIT_* (internal/config)        role splitter configuration, incl. the
//	                                 shared secret (64-hex; SPLIT_SECRET)
//	SPLITTERCTL_SPLITTER_BIN         absolute path of the splitter binary
//	SPLITTERCTL_SPLITTER_VERSION     splitter version
//	Germany:
//	SPLITTERCTL_XRAY_VERSION         Xray version (default: the pinned version)
//	SPLITTERCTL_REALITY_SNI          Reality camouflage SNI
//	SPLITTERCTL_REALITY_SHORT_ID     16-hex Reality shortId
//	SPLITTERCTL_REALITY_UUID         RFC 4122 v4 client UUID
//	Iran:
//	SPLITTERCTL_ORIGIN_MODE          caddy | cdn (none is rejected for public)
//	SPLITTERCTL_UPLOAD_DOMAIN        public upload domain
//	SPLITTERCTL_ORIGIN_PORT          cdn only: 1..65535
//	SPLITTERCTL_ACME_EMAIL           caddy only, optional
//	SPLITTERCTL_ACME_CHALLENGE       caddy only: http01 (default) | tlsalpn01
//	SPLITTERCTL_CDN_SECURITY         cdn only: tlsOrigin | plainOrigin
//	SPLITTERCTL_CDN_ORIGIN_TRUST     cdn tlsOrigin only (D9):
//	                                 pullCA | unauthenticatedTLS
//	Both:
//	SPLITTERCTL_FIREWALL_BACKEND     none (default) | ufw | nftables | auto
//	SPLITTERCTL_FW_ALLOW / _DENY     comma-separated TCP ports, applied as
//	                                 project-owned (marker-commented) rules
//
// The origin (Caddy) binary is always the pinned version: the origin
// provider installs the pin, so the CLI deliberately has no origin-version
// knob. Rollback and uninstall re-derive the request from the CURRENT
// role's environment: the manifest stores fingerprints, not secrets, so the
// original deployment environment must still be available (and the rollback
// guards fail closed if anything reconstructible differs from what is
// recorded).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

var errUsage = errors.New("usage error")
var errNotWired = errors.New("command is not wired to host adapters")

// goos is the platform probe behind the Linux gate. It is a var (like
// systemd's managed-path vars) so tests exercise the gate on any host;
// production always sees runtime.GOOS. Only _test.go files reassign it.
var goos = runtime.GOOS

// canonicalStateRoot is the production state root for the mutation
// commands (rollback, uninstall, recover). It is a var — mirroring
// systemd's test-redirectable managed paths — so tests can point it at a
// temporary root. Only _test.go files reassign it (restored via
// t.Cleanup). NewLinuxAdapter independently enforces the canonical
// systemd.StateDir for install requests.
var canonicalStateRoot = systemd.StateDir

// canonicalStore returns the store the mutation commands operate on.
func canonicalStore() (*deploy.Store, error) {
	return deploy.NewStore(canonicalStateRoot)
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// requireLinux gates the mutation commands: the concrete adapters mutate a
// Linux host (systemd, /etc, root). Failing fast on any other platform keeps
// a stray `splitterctl install` on a laptop from touching anything.
func requireLinux(command string) error {
	if goos != "linux" {
		return fmt.Errorf("deploy: %s requires Linux (the target deployment platform)", command)
	}
	return nil
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		printUsage(out)
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	stateRoot := os.Getenv("SPLITTERCTL_STATE_ROOT")
	if stateRoot == "" {
		stateRoot = "/etc/split-tunnel"
	}
	store, err := deploy.NewStore(filepath.Clean(stateRoot))
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return fmt.Errorf("%w: status takes no arguments", errUsage)
		}
		return status(ctx, store, out)
	case "doctor":
		if len(args) != 1 {
			return fmt.Errorf("%w: doctor takes no arguments", errUsage)
		}
		return doctor(ctx, store, out)
	case "config":
		if len(args) == 2 && args[1] == "show" {
			return configShow(ctx, store, out)
		}
		if len(args) < 2 || args[1] != "set" {
			return fmt.Errorf("%w: config supports show or set", errUsage)
		}
		// config set is not wired: in-place reconfiguration of a committed
		// deployment (env-file rewrite + unit re-apply + health gate) needs
		// its own transaction semantics; see IMPLEMENTATION_STATUS.md.
		return notWired(args)
	case "install":
		if len(args) != 2 || (args[1] != deploy.RoleIran && args[1] != deploy.RoleGermany) {
			return fmt.Errorf("%w: install requires exactly iran or germany", errUsage)
		}
		return installCommand(ctx, args[1], out)
	case "pair":
		if len(args) != 2 || (args[1] != "generate" && args[1] != "apply" && args[1] != "finalize") {
			return fmt.Errorf("%w: pair requires generate, apply, or finalize", errUsage)
		}
		return pairCommand(ctx, store, args[1], out)
	case "upgrade":
		if len(args) > 2 || (len(args) == 2 && !isUpgradeTarget(args[1])) {
			return fmt.Errorf("%w: upgrade accepts at most one of --xray, --origin, or --splitter", errUsage)
		}
		// upgrade is not wired: component-level upgrades (xray pointer
		// re-point, origin re-pin, splitter re-apply) must be planned as
		// their own desired-state transactions with component-scoped
		// recovery; see IMPLEMENTATION_STATUS.md.
		return notWired(args)
	case "rollback":
		if len(args) != 3 || args[1] != "--to" || args[2] == "" || strings.ContainsAny(args[2], `/\\`) {
			return fmt.Errorf("%w: rollback requires --to state-id", errUsage)
		}
		return rollbackCommand(ctx, args[2], out)
	case "uninstall":
		if len(args) > 2 || (len(args) == 2 && args[1] != "--purge") {
			return fmt.Errorf("%w: uninstall accepts only --purge", errUsage)
		}
		return uninstallCommand(ctx, len(args) == 2, out)
	case "recover":
		if len(args) == 1 {
			return recoverCommand(false, out)
		}
		if len(args) == 2 && args[1] == "--ack" {
			return recoverCommand(true, out)
		}
		return fmt.Errorf("%w: recover accepts only --ack", errUsage)
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
}

func notWired(args []string) error {
	return fmt.Errorf("%w: %s", errNotWired, strings.Join(args, " "))
}

func isUpgradeTarget(arg string) bool {
	switch arg {
	case "--xray", "--origin", "--splitter":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Mutation commands
// ---------------------------------------------------------------------------

// installCommand runs the full desired-state transaction for one role. The
// request is built from the environment contract and the canonical T5 paths;
// the adapter and controller are constructed fresh per invocation (no
// cross-command state).
func installCommand(ctx context.Context, role string, out io.Writer) error {
	if err := requireLinux("install"); err != nil {
		return err
	}
	request, err := installRequestFromEnv(role)
	if err != nil {
		return err
	}
	adapter, err := deploy.NewLinuxAdapter(request, systemd.OSExecutor{}, firewall.OSExecutor{})
	if err != nil {
		return err
	}
	controller := &deploy.Controller{Store: adapter.Store, Adapter: adapter}
	result, err := controller.ApplyRequest(ctx, request)
	if err != nil {
		return err
	}
	m := result.Manifest
	if result.Plan.Unchanged {
		_, _ = fmt.Fprintf(out, "install: already converged (no changes)\nrole: %s\ngeneration: %s\n", m.Role, m.Generation)
		return nil
	}
	// Deliberately summary-only: no paths, hashes, or key material.
	_, _ = fmt.Fprintf(out, "install: committed\nrole: %s\ngeneration: %s\nrevisions: %d\nservices: %d\nfirewall: %s\n",
		m.Role, m.Generation, len(m.Revisions), len(m.Services), m.Firewall.Backend)
	return nil
}

// rollbackCommand converges the host to a retained revision and commits a
// new "rollback" revision only after the host is healthy. The request is
// re-derived from the current role's environment (the manifest stores
// fingerprints, not secrets); the adapter's rollback guards fail closed if
// the environment no longer matches the recorded deployment.
func rollbackCommand(ctx context.Context, revisionID string, out io.Writer) error {
	if err := requireLinux("rollback"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	current, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("rollback: nothing installed (no committed state)")
		}
		return fmt.Errorf("rollback: load deployment state: %w", err)
	}
	request, err := installRequestFromEnv(current.Role)
	if err != nil {
		return err
	}
	adapter, err := deploy.NewLinuxAdapter(request, systemd.OSExecutor{}, firewall.OSExecutor{})
	if err != nil {
		return err
	}
	controller := &deploy.Controller{Store: store, Adapter: adapter}
	committed, err := controller.Rollback(ctx, revisionID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "rollback: committed\nrole: %s\ngeneration: %s\ntarget: %s\n", committed.Role, committed.Generation, revisionID)
	return nil
}

// uninstallCommand tears down the committed deployment (units, firewall,
// env/config files) and removes the state manifest only after the host is
// clean. Without --purge the revision history is retained as evidence.
func uninstallCommand(ctx context.Context, purge bool, out io.Writer) error {
	if err := requireLinux("uninstall"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	current, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("uninstall: nothing installed (no committed state)")
		}
		return fmt.Errorf("uninstall: load deployment state: %w", err)
	}
	request, err := installRequestFromEnv(current.Role)
	if err != nil {
		return err
	}
	adapter, err := deploy.NewLinuxAdapter(request, systemd.OSExecutor{}, firewall.OSExecutor{})
	if err != nil {
		return err
	}
	controller := &deploy.Controller{Store: store, Adapter: adapter}
	if err := controller.Uninstall(ctx, purge); err != nil {
		return err
	}
	if purge {
		_, _ = fmt.Fprintln(out, "uninstall: deployment removed (state and revision history purged)")
	} else {
		_, _ = fmt.Fprintln(out, "uninstall: deployment removed (revision history retained as evidence)")
	}
	return nil
}

// recoverCommand reports the in-flight journal left by a failed mutation
// and, with --ack, clears it after the operator has verified the host. The
// journal is deliberately retained after EVERY failed transaction (even
// when in-process recovery succeeded) as the ownership record: the ack is
// the explicit operator acknowledgement that recovery is complete. Without
// it, install/rollback fail closed on the stale journal.
func recoverCommand(ack bool, out io.Writer) error {
	if err := requireLinux("recover"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	journal, err := store.ReadJournal()
	if err != nil {
		if os.IsNotExist(err) {
			if ack {
				return errors.New("recover: no in-flight journal to acknowledge")
			}
			_, _ = fmt.Fprintln(out, "recover: no in-flight journal (nothing in flight)")
			return nil
		}
		return fmt.Errorf("recover: read journal: %w", err)
	}
	// The journal is ownership-scoped and secret-free by construction, so
	// echoing it is safe (unit/file names and a pending generation only).
	_, _ = fmt.Fprintf(out, "in-flight journal:\nrole: %s\ngeneration: %s\nunits: %s\npreUnits: %s\nfiles: %s\npreFiles: %s\nfirewallApplied: %v\n",
		journal.Role, journal.Generation,
		joinOrNone(journal.Units), joinOrNone(journal.PreUnits),
		joinOrNone(journal.Files), joinOrNone(journal.PreFiles),
		journal.Firewall)
	if !ack {
		_, _ = fmt.Fprintln(out, "verify the host against this journal, then run: splitterctl recover --ack")
		return nil
	}
	if err := store.ClearJournal(); err != nil {
		return fmt.Errorf("recover: clear journal: %w", err)
	}
	_, _ = fmt.Fprintln(out, "recover: journal cleared; mutations are unblocked (run status and doctor to verify)")
	return nil
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

// ---------------------------------------------------------------------------
// Environment → InstallRequest
// ---------------------------------------------------------------------------

// Mutation environment variable names (single source of truth for the
// contract documented in the package comment).
const (
	envSplitterBin     = "SPLITTERCTL_SPLITTER_BIN"
	envSplitterVersion = "SPLITTERCTL_SPLITTER_VERSION"
	envXrayVersion     = "SPLITTERCTL_XRAY_VERSION"
	envRealitySNI      = "SPLITTERCTL_REALITY_SNI"
	envRealityShortID  = "SPLITTERCTL_REALITY_SHORT_ID"
	envRealityUUID     = "SPLITTERCTL_REALITY_UUID"
	envOriginMode      = "SPLITTERCTL_ORIGIN_MODE"
	envUploadDomain    = "SPLITTERCTL_UPLOAD_DOMAIN"
	envCDNOriginPort   = "SPLITTERCTL_ORIGIN_PORT"
	envACMEEmail       = "SPLITTERCTL_ACME_EMAIL"
	envACMEChallenge   = "SPLITTERCTL_ACME_CHALLENGE"
	envCDNSecurity     = "SPLITTERCTL_CDN_SECURITY"
	envCDNOriginTrust  = "SPLITTERCTL_CDN_ORIGIN_TRUST"
	envFirewallBackend = "SPLITTERCTL_FIREWALL_BACKEND"
	envFirewallAllow   = "SPLITTERCTL_FW_ALLOW"
	envFirewallDeny    = "SPLITTERCTL_FW_DENY"
)

// installRequestFromEnv maps the operator environment to the complete,
// canonical-path InstallRequest for one role. It performs no host action.
// Every error names the offending environment variable (or field), never a
// value: the shared secret and Reality key material never reach an error
// string.
func installRequestFromEnv(role string) (deploy.InstallRequest, error) {
	var request deploy.InstallRequest
	cfg, err := config.Load(role)
	if err != nil {
		return request, fmt.Errorf("install: %w", err)
	}
	request.Role = role
	request.Config = *cfg
	// Canonical T5 paths (the production adapter enforces these; NewLinux
	// Adapter rejects non-canonical requests).
	request.StateRoot = systemd.StateDir
	request.EnvPath = systemd.EnvFile(systemd.Role(role))

	splitterBin := strings.TrimSpace(os.Getenv(envSplitterBin))
	splitterVersion := strings.TrimSpace(os.Getenv(envSplitterVersion))
	if !filepath.IsAbs(splitterBin) {
		return request, fmt.Errorf("install: %s must be set to an absolute path", envSplitterBin)
	}
	if splitterVersion == "" {
		return request, fmt.Errorf("install: %s must be set", envSplitterVersion)
	}
	request.SplitterPath = splitterBin
	request.SplitterVersion = splitterVersion

	request.Firewall, err = firewallPlanFromEnv(role)
	if err != nil {
		return request, err
	}

	switch role {
	case deploy.RoleGermany:
		xrayVersion := strings.TrimSpace(os.Getenv(envXrayVersion))
		if xrayVersion == "" {
			xrayVersion = xray.PinnedVersion
		}
		request.XrayVersion = xrayVersion
		request.XrayPath = systemd.BinaryPrefix + "/xray/" + xrayVersion + "/xray"
		request.ConfigPath = systemd.StateDir + "/xray-germany.json"
		reality := xray.RealityParams{
			SNI:     strings.TrimSpace(os.Getenv(envRealitySNI)),
			ShortID: strings.TrimSpace(os.Getenv(envRealityShortID)),
			UUID:    strings.TrimSpace(os.Getenv(envRealityUUID)),
		}
		var missing []string
		if reality.SNI == "" {
			missing = append(missing, envRealitySNI)
		}
		if reality.ShortID == "" {
			missing = append(missing, envRealityShortID)
		}
		if reality.UUID == "" {
			missing = append(missing, envRealityUUID)
		}
		if len(missing) > 0 {
			return request, fmt.Errorf("install: Germany requires %s", strings.Join(missing, ", "))
		}
		request.Reality = reality
	case deploy.RoleIran:
		plan, err := originPlanFromEnv(cfg)
		if err != nil {
			return request, err
		}
		request.Origin = plan
		// The origin provider installs exactly the pinned Caddy version,
		// so the manifest version and binary path are fixed to the pin
		// (no operator knob — a mismatch would diverge from what T4
		// actually installs).
		request.OriginVersion = origin.PinnedVersion
		request.OriginPath = systemd.BinaryPrefix + "/caddy/" + origin.PinnedVersion + "/caddy"
		if plan.Mode == origin.ModeCaddy || (plan.Mode == origin.ModeCDN && plan.CDNSecurity == origin.CDNTLSOrigin) {
			request.ConfigPath = systemd.StateDir + "/Caddyfile"
		}
	default:
		return request, fmt.Errorf("install: invalid role %q", role)
	}
	return request, nil
}

// originPlanFromEnv builds the Iran origin plan from the environment. The
// upstream is derived from the role's WsListen (the origin fronts the local
// WS listener, loopback only); cdn plainOrigin (mode B) has no upstream.
func originPlanFromEnv(cfg *config.Config) (origin.Plan, error) {
	mode := strings.TrimSpace(os.Getenv(envOriginMode))
	switch mode {
	case string(origin.ModeCaddy), string(origin.ModeCDN):
	case "":
		return origin.Plan{}, fmt.Errorf("install: %s must be set (caddy or cdn)", envOriginMode)
	case string(origin.ModeNone):
		return origin.Plan{}, fmt.Errorf("install: origin mode %q is not allowed for a public Iran deployment", mode)
	default:
		return origin.Plan{}, fmt.Errorf("install: %s must be caddy or cdn", envOriginMode)
	}
	plan := origin.Plan{Mode: origin.Mode(mode)}
	plan.Domain = strings.TrimSpace(os.Getenv(envUploadDomain))
	switch plan.Mode {
	case origin.ModeCaddy:
		// Caddy is fixed to 443 (ACME); OriginPort stays 0.
		if email := strings.TrimSpace(os.Getenv(envACMEEmail)); email != "" {
			plan.ACMEEmail = email
		}
		switch challenge := strings.TrimSpace(os.Getenv(envACMEChallenge)); challenge {
		case "":
			plan.ACMEChallenge = origin.ACMEHTTP01
		case string(origin.ACMEHTTP01), string(origin.ACMETLSALPN01):
			plan.ACMEChallenge = origin.ACMEChallenge(challenge)
		default:
			return origin.Plan{}, fmt.Errorf("install: %s must be http01 or tlsalpn01", envACMEChallenge)
		}
	case origin.ModeCDN:
		switch security := strings.TrimSpace(os.Getenv(envCDNSecurity)); security {
		case "":
			return origin.Plan{}, fmt.Errorf("install: %s must be set (tlsOrigin or plainOrigin)", envCDNSecurity)
		case string(origin.CDNTLSOrigin):
			plan.CDNSecurity = origin.CDNTLSOrigin
			switch trust := strings.TrimSpace(os.Getenv(envCDNOriginTrust)); trust {
			case "":
				return origin.Plan{}, fmt.Errorf("install: %s is required for cdn tlsOrigin (pullCA or unauthenticatedTLS)", envCDNOriginTrust)
			case string(origin.CDNOriginTrustPullCA), string(origin.CDNOriginTrustUnauthenticated):
				plan.CDNOriginTrust = origin.CDNOriginTrust(trust)
			default:
				return origin.Plan{}, fmt.Errorf("install: %s must be pullCA or unauthenticatedTLS", envCDNOriginTrust)
			}
		case string(origin.CDNPlainOrigin):
			plan.CDNSecurity = origin.CDNPlainOrigin
		default:
			return origin.Plan{}, fmt.Errorf("install: %s must be tlsOrigin or plainOrigin", envCDNSecurity)
		}
		port, err := cdnOriginPortFromEnv()
		if err != nil {
			return origin.Plan{}, err
		}
		plan.OriginPort = port
	}
	switch {
	case plan.Mode == origin.ModeCDN && plan.CDNSecurity == origin.CDNPlainOrigin:
		// Mode B: the CDN talks straight to the splitter; no local
		// upstream (UpstreamAddr is ignored by the provider).
	default:
		upstream, err := originUpstreamFromWsListen(cfg.WsListen)
		if err != nil {
			return origin.Plan{}, err
		}
		plan.UpstreamAddr = upstream
	}
	return plan, nil
}

// cdnOriginPortFromEnv parses the cdn origin port (1..65535). Caddy mode is
// fixed to 443 and never reads this variable.
func cdnOriginPortFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv(envCDNOriginPort))
	if raw == "" {
		return 0, fmt.Errorf("install: %s must be set (a port between 1 and 65535)", envCDNOriginPort)
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("install: %s must be a port between 1 and 65535", envCDNOriginPort)
	}
	return port, nil
}

// originUpstreamFromWsListen canonicalizes the splitter's WS listener into
// the loopback upstream the origin fronts. An empty host (bind-all) is
// fronted at 127.0.0.1; a non-loopback host is a topology mismatch the
// origin refuses (it only ever dials 127.0.0.1/::1).
func originUpstreamFromWsListen(wsListen string) (string, error) {
	host, portStr, err := net.SplitHostPort(wsListen)
	if err != nil {
		return "", fmt.Errorf("install: %s is not a valid host:port", config.EnvWsListen)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("install: the origin can only front a loopback %s", config.EnvWsListen)
	}
	return net.JoinHostPort(ip.String(), portStr), nil
}

// firewallPlanFromEnv builds the project-owned firewall plan. The backend
// defaults to none (the product touches no host firewall); rules are
// comma-separated decimal TCP ports and always carry the project marker.
func firewallPlanFromEnv(role string) (firewall.Plan, error) {
	raw := strings.TrimSpace(os.Getenv(envFirewallBackend))
	if raw == "" {
		raw = string(firewall.BackendNone)
	}
	switch b := firewall.Backend(raw); b {
	case firewall.BackendNone, firewall.BackendUFW, firewall.BackendNFT, firewall.BackendAuto:
	default:
		return firewall.Plan{}, fmt.Errorf("install: %s must be none, ufw, nftables, or auto", envFirewallBackend)
	}
	plan := firewall.Plan{Backend: firewall.Backend(raw), Role: role}
	allow, err := firewallRulesFromEnv(envFirewallAllow, "allow")
	if err != nil {
		return firewall.Plan{}, err
	}
	plan.Allow = allow
	deny, err := firewallRulesFromEnv(envFirewallDeny, "deny")
	if err != nil {
		return firewall.Plan{}, err
	}
	plan.Deny = deny
	return plan, nil
}

// firewallRulesFromEnv parses comma-separated decimal TCP ports into
// project-owned rules (protocol tcp fixed: T6's rule set is TCP-only).
func firewallRulesFromEnv(name, action string) ([]firewall.Rule, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	var rules []firewall.Rule
	for _, part := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("install: %s entries must be decimal TCP ports between 1 and 65535", name)
		}
		rules = append(rules, firewall.Rule{Port: port, Protocol: "tcp", Action: action, Comment: firewall.Marker})
	}
	return rules, nil
}

// ---------------------------------------------------------------------------
// Read-only commands
// ---------------------------------------------------------------------------

func pairCommand(_ context.Context, store *deploy.Store, action string, out io.Writer) error {
	manifest, err := store.Load()
	if err != nil {
		return fmt.Errorf("pair: load deployment state: %w", err)
	}
	p := deploy.Pairing{Store: store}
	var state deploy.PairingState
	var blob string
	switch action {
	case "generate":
		if manifest.Role != deploy.RoleIran {
			return fmt.Errorf("pair: generate is currently supported on Iran; Germany requires provisioned Reality public parameters")
		}
		secretPath := os.Getenv("SPLITTERCTL_SECRET_FILE")
		domain := os.Getenv("SPLITTERCTL_UPLOAD_DOMAIN")
		if secretPath == "" || domain == "" || !filepath.IsAbs(secretPath) {
			return fmt.Errorf("pair: set absolute SPLITTERCTL_SECRET_FILE and SPLITTERCTL_UPLOAD_DOMAIN")
		}
		secretBytes, err := os.ReadFile(secretPath)
		if err != nil {
			return fmt.Errorf("pair: read protected secret file: %w", err)
		}
		blob, state, err = p.GenerateA(strings.TrimSpace(string(secretBytes)), domain)
		if err != nil {
			return err
		}
	case "apply", "finalize":
		blobPath := os.Getenv("SPLITTERCTL_PAIR_BLOB_FILE")
		if blobPath == "" || !filepath.IsAbs(blobPath) {
			return fmt.Errorf("pair: set absolute SPLITTERCTL_PAIR_BLOB_FILE")
		}
		data, err := os.ReadFile(blobPath)
		if err != nil {
			return fmt.Errorf("pair: read blob file: %w", err)
		}
		encoded := strings.TrimSpace(string(data))
		if manifest.Role == deploy.RoleGermany {
			if action != "apply" {
				return fmt.Errorf("pair: Germany accepts only pair apply for Blob A")
			}
			_, state, err = p.ApplyA(encoded)
		} else {
			if action != "finalize" {
				return fmt.Errorf("pair: Iran accepts only pair finalize for Blob B")
			}
			_, state, err = p.ApplyB(encoded)
		}
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported pair action", errUsage)
	}
	manifest.Pairing = state
	committed, err := store.Commit(manifest, "pair-"+action)
	if err != nil {
		return err
	}
	if blob != "" {
		_, _ = fmt.Fprintln(out, blob)
	} else {
		_, _ = fmt.Fprintf(out, "pairing: %s\nfingerprint: %s\ngeneration: %s\n", state.State, state.Fingerprints[0], committed.Generation)
	}
	return nil
}

func status(_ context.Context, store *deploy.Store, out io.Writer) error {
	m, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(out, "status: not installed")
			return nil
		}
		return err
	}
	_, _ = fmt.Fprintf(out, "role: %s\ngeneration: %s\nupdated: %s\n", m.Role, m.Generation, m.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
	_, _ = fmt.Fprintf(out, "services: %d\nrevisions: %d\nfirewall: %s\n", len(m.Services), len(m.Revisions), m.Firewall.Backend)
	return nil
}

func doctor(ctx context.Context, store *deploy.Store, out io.Writer) error {
	findings := (deploy.Diagnostics{Store: store}).Run(ctx)
	for _, f := range findings {
		_, _ = fmt.Fprintf(out, "%s [%s] %s", f.ID, f.Severity, f.Summary)
		if f.Action != "" {
			_, _ = fmt.Fprintf(out, "; action: %s", f.Action)
		}
		_, _ = fmt.Fprintln(out)
	}
	if deploy.HasFailures(findings) {
		return errors.New("doctor: one or more checks failed")
	}
	return nil
}

func configShow(_ context.Context, store *deploy.Store, out io.Writer) error {
	m, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config: not installed")
		}
		return err
	}
	// Deliberately omit pairing fingerprints, paths, and component hashes: this
	// command is operator-readable and must not become a secret or topology dump.
	_, _ = fmt.Fprintf(out, "role: %s\n", m.Role)
	_, _ = fmt.Fprintf(out, "splitter.version: %s\n", m.Components.Splitter.Version)
	_, _ = fmt.Fprintf(out, "xray.version: %s\n", m.Components.Xray.Version)
	_, _ = fmt.Fprintf(out, "origin.mode: %s\n", m.Components.Origin.Mode)
	_, _ = fmt.Fprintf(out, "origin.domain: %s\n", m.Components.Origin.Domain)
	_, _ = fmt.Fprintf(out, "firewall.backend: %s\n", m.Firewall.Backend)
	_, _ = fmt.Fprintf(out, "pairing.state: %s\n", m.Pairing.State)
	return nil
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "usage: splitterctl <install|pair|status|doctor|upgrade|rollback|uninstall|recover|config>")
	fmt.Fprintln(out, "  status                              show persisted deployment state (SPLITTERCTL_STATE_ROOT)")
	fmt.Fprintln(out, "  doctor                              run read-only deployment checks")
	fmt.Fprintln(out, "  install iran|germany                install a role (Linux root; env contract in package docs)")
	fmt.Fprintln(out, "  pair generate|apply|finalize        exchange pairing blobs")
	fmt.Fprintln(out, "  upgrade [--xray|--origin|--splitter]  (not wired: see IMPLEMENTATION_STATUS.md)")
	fmt.Fprintln(out, "  rollback --to state-id              converge the host to a retained revision (Linux root)")
	fmt.Fprintln(out, "  uninstall [--purge]                 remove the deployment (Linux root)")
	fmt.Fprintln(out, "  recover [--ack]                     report / acknowledge an in-flight journal (Linux root)")
	fmt.Fprintln(out, "  config show|set                     show (wired) / set (not wired) deployment config")
}
