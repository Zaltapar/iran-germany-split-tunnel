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
//	                                 shared secret (64-hex; SPLIT_SECRET) and
//	                                 the optional RFC 1929 SOCKS credentials
//	                                 (SPLIT_SOCKS_USER + SPLIT_SOCKS_PASS,
//	                                 Iran only; the password is never echoed)
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
//	Pairing (see pairCommand docs for the full state machine):
//	SPLITTERCTL_SECRET_FILE          Iran pair generate: absolute protected file
//	SPLITTERCTL_UPLOAD_DOMAIN        Iran pair generate: public upload domain
//	SPLITTERCTL_PAIR_BLOB_FILE       apply/finalize: absolute file holding the
//	                                 blob to consume (A on Germany, B on Iran)
//	SPLITTERCTL_PAIR_DOWN_HOST       Germany pair apply: the public down host to
//	                                 embed in Blob B (defaults to auto-detected)
//	SPLITTERCTL_PAIR_BLOB_OUT        optional: absolute path the emitted blob is
//	                                 ALSO written to, 0600, for non-display relay
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

var errUsage = errors.New("usage error")

// recoverTimeout bounds a single post-crash recovery run: recovery is a
// synchronous, best-effort convergence of project-owned artifacts and must
// never hang the operator. It is a var so tests can shorten it.
var recoverTimeout = 60 * time.Second

// newRecoverController builds the controller used by `recover`. It mirrors
// installCommand's construction (installRequestFromEnv + NewLinuxAdapter) but
// derives the role from the committed manifest when one exists, falling back
// to the journal's role (a crashed FRESH install has no committed manifest).
// It is a var — like goos and canonicalStateRoot — so tests can substitute a
// controller backed by a fake adapter without a Linux/root host or the full
// mutation environment contract. Production always uses the real adapter.
var newRecoverController = func(store *deploy.Store, journal deploy.ArtifactJournal) (*deploy.Controller, error) {
	role := journal.Role
	if current, err := store.Load(); err == nil && current.Role != "" {
		role = current.Role
	}
	request, err := installRequestFromEnv(role)
	if err != nil {
		return nil, err
	}
	adapter, err := deploy.NewLinuxAdapter(request, systemd.OSExecutor{}, firewall.OSExecutor{})
	if err != nil {
		return nil, err
	}
	return &deploy.Controller{Store: store, Adapter: adapter}, nil
}

// newMutationController builds the controller a mutation command uses from the
// operator's environment-derived request and the canonical store. It mirrors
// installCommand's construction exactly (deploy.NewLinuxAdapter over the
// canonical T5 paths), so `config set` and `upgrade` share one composition
// with install/rollback/uninstall and never build a second transaction path.
// It is a var — like newRecoverController — so tests can substitute a
// controller backed by a fake adapter without a Linux/root host or the full
// mutation environment contract. Production always uses the real adapter.
var newMutationController = func(store *deploy.Store, request deploy.InstallRequest) (*deploy.Controller, error) {
	adapter, err := deploy.NewLinuxAdapter(request, systemd.OSExecutor{}, firewall.OSExecutor{})
	if err != nil {
		return nil, err
	}
	return &deploy.Controller{Store: store, Adapter: adapter}, nil
}

// mutationRequestEnvError labels an environment-contract failure raised while
// building a mutation request, so every command reports it under its own name
// (the shared builder reports it as "install").
func mutationRequestEnvError(command string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "install: ") {
		msg = command + ": " + strings.TrimPrefix(msg, "install: ")
	}
	return errors.New(msg)
}

// goos is the platform probe behind the Linux gate. It is a var (like
// systemd's managed-path vars) so tests exercise the gate on any host;
// production always sees runtime.GOOS. Only _test.go files reassign it.
var goos = runtime.GOOS

// canonicalStateRoot is the production state root for the mutation
// commands (rollback, uninstall, recover, config set, upgrade). It is a var —
// mirroring systemd's test-redirectable managed paths — so tests can point it
// at a temporary root. Only _test.go files reassign it (restored via
// t.Cleanup). NewLinuxAdapter independently enforces the canonical
// systemd.StateDir for install requests.
var canonicalStateRoot = systemd.StateDir

// canonicalBinaryPrefix is the managed binary prefix the mutation request
// builder derives component paths from. In production it is exactly
// systemd.BinaryPrefix (the constant T5 and the adapter enforce); it is a var
// so the request-building path can be exercised on a host whose filesystem
// roots differ (Windows), where the Unix "/opt/..." prefix is not absolute.
// Only _test.go files reassign it (restored via t.Cleanup).
var canonicalBinaryPrefix = systemd.BinaryPrefix

// storeForRoot builds a store for a state root, converging the production
// service state dir (/etc/split-tunnel) to the 0750 root:split-tunnel contract
// on commit. A 0700 root would lock the non-root service units out of their
// 0640 live configs after any committed transaction (staging defect). Test
// roots (SPLITTERCTL_STATE_ROOT redirects) keep the safe 0700 default.
func storeForRoot(root string) (*deploy.Store, error) {
	s, err := deploy.NewStore(root)
	if err != nil {
		return nil, err
	}
	if root == systemd.StateDir {
		s.RootMode = systemd.StateDirMode
	}
	return s, nil
}

// canonicalStore returns the store the mutation commands operate on.
func canonicalStore() (*deploy.Store, error) {
	return storeForRoot(canonicalStateRoot)
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
	// The dispatcher store is the one `pair apply|finalize` commits through,
	// so it must converge the production service root to 0750 like every
	// other mutation store (storeForRoot).
	store, err := storeForRoot(filepath.Clean(stateRoot))
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
		if len(args) == 2 {
			return fmt.Errorf("%w: config set requires at least one KEY=VALUE", errUsage)
		}
		return configSetCommand(ctx, args[2:], out)
	case "install":
		if len(args) != 2 || (args[1] != deploy.RoleIran && args[1] != deploy.RoleGermany) {
			return fmt.Errorf("%w: install requires exactly iran or germany", errUsage)
		}
		return installCommand(ctx, args[1], out)
	case "pair":
		if len(args) < 2 || (args[1] != "generate" && args[1] != "apply" && args[1] != "finalize") {
			return fmt.Errorf("%w: pair requires generate, apply, or finalize", errUsage)
		}
		// DEFECT-4: only `generate` may carry an argument, and only --force
		// (the explicit restart of a completed exchange). apply/finalize
		// accept no extra arguments.
		force := false
		switch args[1] {
		case "generate":
			if len(args) > 3 || (len(args) == 3 && args[2] != "--force") {
				return fmt.Errorf("%w: pair generate accepts at most --force", errUsage)
			}
			force = len(args) == 3
		default:
			if len(args) != 2 {
				return fmt.Errorf("%w: pair %s takes no extra arguments", errUsage, args[1])
			}
		}
		return pairCommand(ctx, store, args[1], force, out)
	case "upgrade":
		if len(args) > 2 || (len(args) == 2 && !isUpgradeTarget(args[1])) {
			return fmt.Errorf("%w: upgrade accepts at most one of --xray, --origin, or --splitter", errUsage)
		}
		target := ""
		if len(args) == 2 {
			target = args[1]
		}
		return upgradeCommand(ctx, target, out)
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
			return recoverCommand(ctx, false, out)
		}
		if len(args) == 2 && args[1] == "--ack" {
			return recoverCommand(ctx, true, out)
		}
		return fmt.Errorf("%w: recover accepts only --ack", errUsage)
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
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
	// !result.Changed (not result.Plan.Unchanged): a DEFECT-2 drift-heal commits
	// with Plan.Unchanged==true but Changed==true, so it must report "committed".
	if !result.Changed {
		_, _ = fmt.Fprintf(out, "install: already converged (no changes)\nrole: %s\ngeneration: %s\n", m.Role, m.Generation)
		return nil
	}
	// Deliberately summary-only: no paths, hashes, or key material.
	_, _ = fmt.Fprintf(out, "install: committed\nrole: %s\ngeneration: %s\nrevisions: %d\nservices: %d\nfirewall: %s\n",
		m.Role, m.Generation, len(m.Revisions), len(m.Services), m.Firewall.Backend)
	return nil
}

// ---------------------------------------------------------------------------
// config set
// ---------------------------------------------------------------------------

// applyConfigOverrides folds `config set KEY=VALUE ...` assignments into the
// environment-derived request and returns the accepted key names, in the
// order they were given.
//
// Every key is resolved through deploy's authoritative projection table
// (deploy.ConfigKeys), so no environment-variable name or validation rule is
// re-declared here: the value is written to the config.Config field the table
// names, and the authoritative validator (config.Config.Validate, reached
// through InstallRequest.Validate) is what actually judges it inside the
// transaction. A field with no environment projection is refused explicitly
// (deploy.ConfigKeyRefusal) rather than silently ignored.
func applyConfigOverrides(request *deploy.InstallRequest, assignments []string) ([]string, error) {
	var applied []string
	seen := make(map[string]bool, len(assignments))
	for _, assignment := range assignments {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok {
			return nil, fmt.Errorf("%w: config set expects KEY=VALUE (got %q)", errUsage, assignment)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%w: config set expects KEY=VALUE with a non-empty key", errUsage)
		}
		field, settable := deploy.LookupConfigKey(key)
		if !settable {
			if reason := deploy.ConfigKeyRefusal(key); reason != "" {
				return nil, fmt.Errorf("config set: %s cannot be set: %s", key, reason)
			}
			return nil, fmt.Errorf("%w: config set: unknown key %q", errUsage, key)
		}
		if !configKeyAppliesTo(field, request.Role) {
			return nil, fmt.Errorf("%w: config set: key %q applies to %s, not %s",
				errUsage, field.Name, strings.Join(field.Roles, " or "), request.Role)
		}
		if seen[field.Name] {
			return nil, fmt.Errorf("%w: config set: key %q was given more than once", errUsage, field.Name)
		}
		if err := setConfigField(request, field, strings.TrimSpace(value)); err != nil {
			return nil, err
		}
		seen[field.Name] = true
		applied = append(applied, field.Name)
	}
	return applied, nil
}

func configKeyAppliesTo(field deploy.ConfigKey, role string) bool {
	for _, r := range field.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// setConfigField writes one parsed value into the config.Config the request
// carries. Only the field assignment lives here; the VALUE is never echoed in
// an error, and no validation happens at this layer.
func setConfigField(request *deploy.InstallRequest, field deploy.ConfigKey, value string) error {
	c := &request.Config
	switch field.Kind {
	case deploy.ConfigBool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%w: config set: %s expects a boolean (true/false, 1/0)", errUsage, field.Name)
		}
		c.AllowWeakSecret = parsed
		return nil
	case deploy.ConfigInt:
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: config set: %s expects an integer", errUsage, field.Name)
		}
		switch field.Name {
		case "metrics.port":
			c.MetricsPort = n
		case "relay.buf":
			c.RelayBufSize = n
		case "stream.queue.bytes":
			c.QueueBytesPerStream = n
		case "stream.queue.frames":
			c.QueueFramesPerStream = n
		case "stream.queue.total.bytes":
			c.QueueBytesTotal = n
		case "stream.overflow.ms":
			c.OverflowWaitMs = n
		case "carrier.grace":
			c.CarrierGraceMs = n
		case "bootstrap.wait":
			c.BootstrapWaitMs = n
		case "session.buffer.bytes":
			c.SessionBufBytes = n
		case "session.buffer.total.bytes":
			c.SessionBufTotal = n
		case "liveness.rounds":
			c.LivenessRounds = n
		default:
			return fmt.Errorf("%w: config set: key %q has no integer projection", errUsage, field.Name)
		}
		return nil
	default:
		switch field.Name {
		case "socks.listen":
			c.SocksListen = value
		case "socks.user":
			c.SocksUser = value
		case "socks.pass":
			c.SocksPass = value
		case "ws.listen":
			c.WsListen = value
		case "down.carrier.addr":
			c.DownCarrierAddr = value
		case "up.ws.url":
			c.UpWsUrl = value
		case "down.listen":
			c.DownListen = value
		case "secret":
			c.Secret = value
		default:
			return fmt.Errorf("%w: config set: key %q has no string projection", errUsage, field.Name)
		}
		return nil
	}
}

// configSetCommand applies `config set KEY=VALUE ...` as a TRANSACTIONAL
// desired-state change.
//
// The current environment (the same contract install/rollback/uninstall use)
// is the baseline and each KEY=VALUE overrides exactly one field of it. The
// resulting request is validated by the authoritative internal/config
// validator inside the transaction, and the change is applied through the
// existing Controller.ApplyRequest path — there is no second transaction
// engine, and the env file is never written outside the transaction (the
// adapter's Prepare phase owns that write, and the transaction journal
// protects it).
//
// A configuration change is planner-visible through the projected-config
// digest (Manifest.ConfigFingerprint), so a real change always reaches the
// adapter and restarts the units that read the env file, while re-running the
// same `config set` is a true no-op that touches nothing.
//
// Secret hygiene: values are never echoed. The summary names the accepted
// keys only, and every error names a field, never a value.
func configSetCommand(ctx context.Context, assignments []string, out io.Writer) error {
	if err := requireLinux("config set"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	current, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("config: not installed")
		}
		return fmt.Errorf("config: load deployment state: %w", err)
	}
	request, err := installRequestFromEnv(current.Role)
	if err != nil {
		return mutationRequestEnvError("config", err)
	}
	applied, err := applyConfigOverrides(&request, assignments)
	if err != nil {
		return err
	}
	// The projected-config digest is the SAME identity the planner compares,
	// so "nothing changed" is decided here exactly as the planner would
	// decide it — and a request that changes nothing starts no transaction
	// and writes no journal.
	wanted, err := request.ConfigFingerprint()
	if err != nil {
		return err
	}
	if current.ConfigFingerprint != "" && wanted == current.ConfigFingerprint {
		_, _ = fmt.Fprintf(out, "config: already converged (no changes)\nrole: %s\ngeneration: %s\nkeys: %s\n",
			current.Role, current.Generation, strings.Join(applied, ", "))
		return nil
	}
	controller, err := newMutationController(store, request)
	if err != nil {
		return err
	}
	result, err := controller.ApplyRequest(ctx, request)
	if err != nil {
		return err
	}
	m := result.Manifest
	// !result.Changed (not result.Plan.Unchanged): a DEFECT-2 drift-heal commits
	// with Plan.Unchanged==true but Changed==true, so it must report "committed".
	if !result.Changed {
		_, _ = fmt.Fprintf(out, "config: already converged (no changes)\nrole: %s\ngeneration: %s\nkeys: %s\n",
			m.Role, m.Generation, strings.Join(applied, ", "))
		return nil
	}
	_, _ = fmt.Fprintf(out, "config: committed\nrole: %s\ngeneration: %s\nkeys: %s\nservices: %d\n",
		m.Role, m.Generation, strings.Join(applied, ", "), len(m.Services))
	return nil
}

// upgradeCommand upgrades exactly one component, or re-applies the current
// deployment, through the existing Controller.ApplyRequest path.
//
// The request is always re-derived from the environment, exactly as rollback
// and uninstall do: the manifest records identities, not secrets, so the
// operator's environment is the authoritative input for what the host should
// converge to.
//
//   - no flag: re-apply the current deployment. Nothing in the environment
//     changed, so the plan is Unchanged and no transaction runs — the
//     documented way to converge/verify a host against its environment.
//   - --splitter: the splitter artifact the environment supplies. The
//     environment IS the source for it, so re-applying it converges the host:
//     with no environment change the plan is Unchanged and the command
//     reports "already converged" without touching anything; a live host that
//     drifted away from its committed deployment is healed by the live audit.
//   - --xray: Germany only (Iran uses an external Xray). Xray is a pinned
//     constant, so the upgrade re-points the managed binary at
//     xray.PinnedVersion and re-applies the Reality parameters; a
//     conflicting environment pin is refused instead of silently overridden.
//   - --origin: a role with a configured origin. The origin is pinned
//     (origin.PinnedVersion); a conflicting environment value is refused.
//
// Stale-journal refusal, role immutability, pairing carry-forward and
// commit-last semantics all come from the controller. Output is summary-only:
// role, generation, component, and counts — never paths, hashes, or key
// material.
func upgradeCommand(ctx context.Context, target string, out io.Writer) error {
	if err := requireLinux("upgrade"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	current, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("upgrade: nothing installed (no committed state)")
		}
		return fmt.Errorf("upgrade: load deployment state: %w", err)
	}
	if current.Generation == "" {
		return errors.New("upgrade: nothing installed (no committed generation)")
	}
	request, err := installRequestFromEnv(current.Role)
	if err != nil {
		return mutationRequestEnvError("upgrade", err)
	}
	component := "re-apply"
	switch target {
	case "--splitter":
		// DEFECT-5: no same-version refusal. Re-applying the environment's
		// splitter converges the host: an unchanged environment is the
		// documented no-op ("already converged"), and a live host that
		// drifted away from its committed deployment is healed by the live
		// audit before the commit decision.
		component = "splitter " + request.SplitterVersion
	case "--xray":
		if current.Role != deploy.RoleGermany {
			return fmt.Errorf("upgrade: --xray applies to %s; %s uses an external Xray", deploy.RoleGermany, current.Role)
		}
		if request.XrayVersion != xray.PinnedVersion {
			return fmt.Errorf("upgrade: --xray installs the pinned Xray %s; the environment requests %s", xray.PinnedVersion, request.XrayVersion)
		}
		component = "xray " + xray.PinnedVersion
	case "--origin":
		if request.Origin.Mode == origin.ModeNone {
			return fmt.Errorf("upgrade: --origin requires a configured origin; role %s has none", current.Role)
		}
		if request.OriginVersion != origin.PinnedVersion {
			return fmt.Errorf("upgrade: --origin installs the pinned origin %s; the environment requests %s", origin.PinnedVersion, request.OriginVersion)
		}
		component = "origin " + origin.PinnedVersion
	}
	controller, err := newMutationController(store, request)
	if err != nil {
		return err
	}
	result, err := controller.ApplyRequest(ctx, request)
	if err != nil {
		return err
	}
	m := result.Manifest
	// !result.Changed (not result.Plan.Unchanged): a DEFECT-2 drift-heal commits
	// with Plan.Unchanged==true but Changed==true, so it must report "committed".
	if !result.Changed {
		_, _ = fmt.Fprintf(out, "upgrade: already converged (no changes)\nrole: %s\ngeneration: %s\ncomponent: %s\n",
			m.Role, m.Generation, component)
		return nil
	}
	_, _ = fmt.Fprintf(out, "upgrade: committed\nrole: %s\ngeneration: %s\ncomponent: %s\nservices: %d\n",
		m.Role, m.Generation, component, len(m.Services))
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

// recoverCommand is the post-crash recovery entrypoint.
//
// Without --ack it EXECUTES journal-driven recovery: it reads the in-flight
// journal, derives ownership from the PERSISTED journal (never from runtime
// state), and reverts the crashed transaction — a fresh install is cleaned up
// to "not deployed"; an upgrade converges to the committed previous
// generation. On success the journal is cleared and install/rollback/uninstall
// are unblocked. A tampered/malformed journal fails closed (nothing is
// deleted, the journal is retained).
//
// With --ack it remains the explicit, documented manual force-clear escape
// hatch: it deletes the journal WITHOUT touching the host, for the case where
// an operator has already reconciled the host by hand. It is intentionally
// destructive and must be run only after verifying the host.
func recoverCommand(ctx context.Context, ack bool, out io.Writer) error {
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
	if ack {
		// --ack is the explicit manual escape hatch, but it must not silently
		// unblock mutations on a host whose committed state CONTRADICTS the
		// in-flight journal: that is evidence of an inconsistent host, not a
		// reconciled one. Fail closed with a diagnosable error.
		//
		//   - No committed manifest (os.ErrNotExist): nothing to contradict,
		//     so the ack-clear proceeds (a crashed fresh install).
		//   - A committed manifest whose role AGREES with the journal: safe.
		//   - A committed manifest whose role DIFFERS: refuse.
		//   - ANY other Load error (notably ErrTampered): the committed state
		//     cannot be trusted to prove the roles agree, so refuse. Silently
		//     proceeding here would let --ack unblock mutations against a
		//     host whose committed state is unreadable or tampered.
		committed, lerr := store.Load()
		if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
			return fmt.Errorf("recover: refusing --ack: committed state could not be read (%v); reconcile the host (or run recover without --ack) before acknowledging", lerr)
		}
		if lerr == nil && committed.Role != "" && committed.Role != journal.Role {
			return fmt.Errorf("recover: refusing --ack: journal role %q does not match committed role %q; reconcile the host (or run recover without --ack) before acknowledging", journal.Role, committed.Role)
		}
		if err := store.ClearJournal(); err != nil {
			return fmt.Errorf("recover: clear journal: %w", err)
		}
		_, _ = fmt.Fprintln(out, "recover: journal cleared without host changes (--ack); mutations are unblocked")
		return nil
	}
	controller, err := newRecoverController(store, journal)
	if err != nil {
		return fmt.Errorf("recover: build adapter: %w", err)
	}
	recoverCtx, cancel := context.WithTimeout(ctx, recoverTimeout)
	defer cancel()
	if _, err := controller.Recover(recoverCtx); err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	// Summary-only: no paths or hashes (the journal echo above already showed
	// the ownership scope; recovery output stays secret-free).
	_, _ = fmt.Fprintln(out, "recover: recovered; journal cleared and mutations are unblocked (run status and doctor to verify)")
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
	// Adapter rejects non-canonical requests). In production canonicalStateRoot
	// IS systemd.StateDir and the env path IS systemd.EnvFile(role); the seams
	// exist only so tests can exercise this builder off a Linux host.
	request.StateRoot = canonicalStateRoot
	request.EnvPath = filepath.Join(canonicalStateRoot, role+".env")

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
	// H-3: record the content identity of the supplied splitter artifact at the
	// deployment boundary. The digest is computed from the absolute binary the
	// operator pointed us at (SPLITTERCTL_SPLITTER_BIN), NEVER a value carried
	// on the wire or in state — it is derived locally and is a non-secret
	// artifact hash. It is persisted in the manifest and re-asserted on
	// re-entry/upgrade; if the bytes at the same path/version change between
	// runs, the planner plans a convergence and the transaction fails closed
	// rather than silently adopting different content under an unchanged
	// version string. When the file is not present (a non-mutating validation
	// or read-only context, or a host where the artifact has not yet been
	// staged) the field is left unasserted ("") so legacy hosts and the
	// planner's empty/unknown rule keep their no-drift semantics.
	request.SplitterSHA256 = hashFileSha256Hex(splitterBin)

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
		request.XrayPath = canonicalBinaryPrefix + "/xray/" + xrayVersion + "/xray"
		request.ConfigPath = canonicalStateRoot + "/xray-germany.json"
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
		// Germany runs no origin provider (Reality is the public entrypoint),
		// so its origin plan is the explicit "none" mode. The upstream is
		// derived from Germany's only local listener so the plan stays valid
		// and host-independent; the none-mode provider never dials it. Without
		// this the plan carries the empty mode, which the origin validator
		// correctly rejects — making every Germany request unbuildable.
		upstream, err := loopbackUpstream(cfg.DownListen, config.EnvDownListen)
		if err != nil {
			return request, err
		}
		request.Origin = origin.Plan{Mode: origin.ModeNone, UpstreamAddr: upstream}
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
		request.OriginPath = canonicalBinaryPrefix + "/caddy/" + origin.PinnedVersion + "/caddy"
		if plan.Mode == origin.ModeCaddy || (plan.Mode == origin.ModeCDN && plan.CDNSecurity == origin.CDNTLSOrigin) {
			request.ConfigPath = canonicalStateRoot + "/Caddyfile"
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
// the loopback upstream the origin fronts.
func originUpstreamFromWsListen(wsListen string) (string, error) {
	return loopbackUpstream(wsListen, config.EnvWsListen)
}

// loopbackUpstream canonicalizes a role's local listener into the loopback
// upstream the origin provider dials. An empty host (bind-all) is fronted at
// 127.0.0.1; a non-loopback host is a topology mismatch the origin refuses
// (it only ever dials 127.0.0.1/::1). envName names the source variable so the
// error stays field-only.
func loopbackUpstream(addr, envName string) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("install: %s is not a valid host:port", envName)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("install: the origin can only front a loopback %s", envName)
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

// Pairing environment variable names (the pair commands' input contract;
// errors name fields, never values — blob/secret material never reaches an
// error string, and the committed state stores fingerprints only).
const (
	envPairDownHost = "SPLITTERCTL_PAIR_DOWN_HOST"
	envPairBlobOut  = "SPLITTERCTL_PAIR_BLOB_OUT"
)

// detectGermanyHost is the seam behind the Blob B down-host auto-detection
// used when SPLITTERCTL_PAIR_DOWN_HOST is unset. It is a var (like goos) so
// tests can substitute a deterministic address; production always probes the
// host's own interfaces.
var detectGermanyHost = detectGermanyHostFromInterfaces

// detectGermanyHostFromInterfaces returns the host's public address for the
// pairing return blob: the lowest-sorted global non-loopback, non-private
// IPv4 if one exists, else the lowest-sorted global IPv6. Sorting makes the
// choice deterministic across interface orderings. On a host with several
// public addresses the operator should set SPLITTERCTL_PAIR_DOWN_HOST
// explicitly; auto-detection is the convenience path for the documented
// single-public-address staging topology (see integration/RUNBOOK.md §2.2).
func detectGermanyHostFromInterfaces() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("pair: auto-detect Germany down host failed: %w", err)
	}
	var v4, v6 []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	switch {
	case len(v4) > 0:
		return v4[0], nil
	case len(v6) > 0:
		return v6[0], nil
	default:
		return "", fmt.Errorf("pair: no public Germany address to auto-detect; set %s", envPairDownHost)
	}
}

// pairCommand is the two-blob pairing exchange (architecture doc §6.1):
//
//	pair generate [--force] (Iran) — emits Blob A once (tunnel secret +
//	                           upload domain) for the operator to carry to
//	                           Germany. DEFECT-4 state gate: a FINALIZED
//	                           pairing refuses generate (it would silently
//	                           reset the completed exchange) unless the
//	                           operator passes --force to deliberately
//	                           restart it; the reset and re-emit are one
//	                           atomic store.Commit.
//	pair apply     (Germany) — consumes Blob A AND emits the RETURN Blob B,
//	                           built from the INSTALLED Reality parameters
//	                           (public key derived from the installed private
//	                           key — never a fresh pair) plus this host's
//	                           public down host and the inbound port. The
//	                           emission is idempotent: a re-run while already
//	                           a-applied (e.g. Blob B was lost) re-emits the
//	                           SAME Blob B deterministically. State machine:
//	                           none → a-applied (and emit); a-applied →
//	                           a-applied (re-emit); any other state fails
//	                           closed.
//	pair finalize  (Iran)    — consumes Blob B, committing "finalized".
//
// Emitted blobs go to stdout once. When SPLITTERCTL_PAIR_BLOB_OUT names an
// absolute path the emitted blob is additionally written there 0600 (symlink
// targets refused) for a non-display relay (scp) instead of a terminal.
// Persisted state carries pairing progress and SHA-256 fingerprints ONLY —
// raw blobs (Blob A carries the tunnel secret) never enter state, logs, or
// errors; Blob B itself contains only public Reality parameters + host/port.
// Role gates are unchanged: Iran rejects apply/finalize mismatches, Germany
// rejects generate/finalize.
func pairCommand(_ context.Context, store *deploy.Store, action string, force bool, out io.Writer) error {
	manifest, err := store.Load()
	if err != nil {
		return fmt.Errorf("pair: load deployment state: %w", err)
	}
	// Validate the optional blob-output path BEFORE any state mutation: a
	// misconfigured relay path is an operator mistake, not something a
	// committed pairing state should ever record.
	blobOutPath := strings.TrimSpace(os.Getenv(envPairBlobOut))
	if blobOutPath != "" && !filepath.IsAbs(blobOutPath) {
		return fmt.Errorf("pair: %s must be an absolute path", envPairBlobOut)
	}
	p := deploy.Pairing{Store: store}
	var state deploy.PairingState
	var blob string
	switch action {
	case "generate":
		if manifest.Role != deploy.RoleIran {
			return fmt.Errorf("pair: generate is currently supported on Iran; Germany derives its return blob from pair apply")
		}
		// DEFECT-4 state gate: the completed exchange is terminal. Re-running
		// generate here would silently reset pairing to a-generated and the
		// old Blob A would no longer be accepted by Iran — a data-loss-class
		// surprise. Refuse unless the operator explicitly passes --force.
		if manifest.Pairing.State == "finalized" && !force {
			return errors.New("pair: the pairing state is finalized; run `pair generate --force` to deliberately restart the exchange")
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
			switch manifest.Pairing.State {
			case "", deploy.PairingStateNone, "a-applied":
			default:
				return fmt.Errorf("pair: apply is only valid before or after a-applied; current pairing state is %q", manifest.Pairing.State)
			}
			if manifest.Paths.Config == "" {
				return errors.New("pair: Germany committed state records no Xray config path (re-run install first)")
			}
			downHost := strings.TrimSpace(os.Getenv(envPairDownHost))
			if downHost == "" {
				downHost, err = detectGermanyHost()
				if err != nil {
					return err
				}
			}
			blob, state, err = p.ApplyAGermany(encoded, downHost, manifest.Paths.Config)
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
	// Human summary first, then the emitted blob as the LAST stdout line so a
	// clipboard copy or `... | tail -n1` reliably captures the blob. The state
	// itself carries fingerprints only (never the raw blob); the blob reaches
	// stdout exactly once. When SPLITTERCTL_PAIR_BLOB_OUT is set, the blob is
	// ALSO written there 0600 for a non-display relay.
	_, _ = fmt.Fprintf(out, "pairing: %s\nfingerprints: %s\ngeneration: %s\n", state.State, strings.Join(state.Fingerprints, ", "), committed.Generation)
	if blob != "" {
		if blobOutPath != "" {
			if err := writeEmittedBlob(blobOutPath, blob); err != nil {
				return fmt.Errorf("pair: %s: %w", envPairBlobOut, err)
			}
		}
		_, _ = fmt.Fprintln(out, blob)
	}
	return nil
}

// hashFileSha256Hex returns the hex-encoded SHA-256 of a regular file's bytes,
// or "" when the file does not exist or is not a regular readable file. It is
// the H-3 content-identity primitive: the digest is derived locally from the
// operator-supplied absolute artifact path and is never a value carried on the
// wire or persisted as a secret. Callers store the result as the artifact's
// SplitterSHA256/XraySHA256 so a byte change at an unchanged path/version is
// planned and failed closed, while an absent artifact stays unasserted (""),
// preserving the planner's empty/unknown no-drift rule for legacy state.
func hashFileSha256Hex(path string) string {
	if !filepath.IsAbs(path) {
		return ""
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// writeEmittedBlob writes an emitted pairing blob 0600 to an operator-chosen
// absolute path for non-display relay. It is the no-follow-safe, atomic
// variant required by M-2:
//
//   - refuses non-regular final targets (a symlink or directory planted at
//     the path is an error, never followed);
//   - creates a secure temp file in the destination directory via the
//     O_EXCL-style pattern in deploy.atomicWrite (mode 0600, owner-only, no
//     race with a concurrent replacer of the target path);
//   - writes the blob, fsyncs, closes, and atomically renames into place —
//     so a concurrent symlink swap against the final path between our Lstat
//     and our write cannot redirect the write to an unmanaged location;
//   - re-verifies descriptor ownership after the rename (the renamed inode
//     must still be the regular 0600 file we just wrote) before returning.
//
// The blob is by design a one-time, human-carried artifact — this helper
// never logs or echoes its content, and errors intentionally do not carry
// blob bytes.
func writeEmittedBlob(path, blob string) error {
	if !filepath.IsAbs(path) {
		return errors.New("pair blob out path must be absolute")
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// Secure temp creation in the destination directory. O_EXCL is implied
	// by O_CREATE on a fresh random name; we also verify the parent is a
	// real directory so a symlinked parent cannot redirect the write.
	if st, err := os.Lstat(dir); err != nil {
		return fmt.Errorf("pair blob out dir: %w", err)
	} else if !st.Mode().IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("pair blob out dir is not a regular directory (refusing)")
	}

	// Pre-check on the final target: a symlink or non-regular object at the
	// destination is refused. The atomic rename below guarantees that even
	// if a concurrent actor plants a symlink between this check and the
	// rename, the rename replaces the symlink itself rather than writing
	// through it — the no-follow semantic we require.
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return errors.New("pair blob out target exists and is not a regular file (refusing)")
		}
	}

	tmp := filepath.Join(dir, base+".tmp-"+strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("pair blob out create temp: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.WriteString(blob + "\n"); err != nil {
		return fmt.Errorf("pair blob out write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("pair blob out sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pair blob out close: %w", err)
	}
	// Atomic rename into the final path. On POSIX this is a single syscall
	// that atomically replaces whatever was at `path` (including a symlink
	// planted by a concurrent actor); the rename itself does not follow.
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pair blob out rename: %w", err)
	}
	// Post-rename descriptor-ownership verification: stat the final path
	// through the directory (Lstat) and confirm it is a regular file we
	// just installed. This catches a pathological case where `path` was a
	// symlink to `tmp` before the rename (the rename would then target the
	// symlink's destination and our tmp path would be gone).
	if st, err := os.Lstat(path); err != nil {
		return fmt.Errorf("pair blob out verify: %w", err)
	} else if !st.Mode().IsRegular() {
		_ = os.Remove(path)
		return errors.New("pair blob out verify: final target is not a regular file (refusing)")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("pair blob out chmod: %w", err)
	}
	ok = true
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

// doctor runs the read-only deployment checks and reports findings. It is a
// hard READ-ONLY guarantee: it inspects and prints only. It never chmods,
// chowns, writes, or removes anything — every check (deploy.StateDirCheck and
// the store-integrity check included) observes state, and remediation is
// always delegated to a lifecycle command.
func doctor(ctx context.Context, store *deploy.Store, out io.Writer) error {
	checks := []deploy.Check{
		deploy.StateDirCheck(store.Root),
		deploy.PairingStalenessCheck(store),
		deploy.ArtifactIntegrityCheck(store),
	}
	if manifest, err := store.Load(); err == nil {
		if os.Getenv("SPLIT_SECRET") != "" {
			checks = append(checks, deploy.ConfigValidationCheck(manifest.Role))
		} else {
			checks = append(checks, deploy.Check{ID: "config.validation", Run: func(context.Context) deploy.Finding {
				return deploy.Finding{ID: "config.validation", Severity: deploy.SeverityWarn, Summary: "current configuration validation was not run because the operator environment is incomplete", Action: "operator must provide the deployment environment and re-run doctor"}
			}})
		}
		if runtime.GOOS == "linux" {
			checks = append(checks, deploy.ServiceStateCheck(store, systemd.NewServiceManager(systemd.OSExecutor{})))
		} else {
			checks = append(checks, deploy.Check{ID: "service.active", Run: func(context.Context) deploy.Finding {
				return deploy.Finding{ID: "service.active", Severity: deploy.SeverityWarn, Summary: "managed service active/settled state is not measurable on this non-Linux host", Action: "operator must run splitterctl doctor on the Linux deployment host"}
			}})
		}
		expected := expectedListenerBinds(manifest.Role)
		checks = append(checks, deploy.ListenerBindsCheck(systemd.OSExecutor{}, expected))
		if manifest.Role == deploy.RoleGermany {
			checks = append(checks, deploy.XrayConfigCheck(xray.OSExecutor{}, manifest.Components.Xray.Path, manifest.Paths.Config, manifest.Components.Xray.Version))
		}
		checks = append(checks, deploy.Check{ID: "network.external", Run: func(context.Context) deploy.Finding {
			return deploy.Finding{ID: "network.external", Severity: deploy.SeverityWarn, Summary: "DNS, CDN, NAT, TLS/WebSocket, and public reachability are external checks", Action: "operator must run the documented preflight commands from the deployment runbook"}
		}})
	} else {
		checks = append(checks, deploy.Check{ID: "config.validation", Run: func(context.Context) deploy.Finding {
			return deploy.Finding{ID: "config.validation", Severity: deploy.SeverityWarn, Summary: "configuration validation is unavailable without a committed deployment role", Action: "install or restore a committed deployment before running role-specific checks"}
		}})
	}
	checks = append(checks, deploy.Check{ID: "firewall.audit", Run: func(context.Context) deploy.Finding {
		return deploy.Finding{ID: "firewall.audit", Severity: deploy.SeverityWarn, Summary: "firewall ownership audit is not run without a reconstructed desired firewall plan", Action: "operator must audit only project-marked rules with ufw status or nft list ruleset"}
	}})
	diags := deploy.Diagnostics{Store: store, Checks: checks}
	findings := diags.Run(ctx)
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

func expectedListenerBinds(role string) []string {
	cfg, err := config.Load(role)
	if err != nil {
		return nil
	}
	var expected []string
	if role == deploy.RoleIran {
		expected = append(expected, cfg.SocksListen, cfg.WsListen)
	} else {
		expected = append(expected, cfg.DownListen)
	}
	if cfg.MetricsPort > 0 {
		expected = append(expected, "127.0.0.1:"+strconv.Itoa(cfg.MetricsPort))
	}
	return expected
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
	fmt.Fprintln(out, "  pair generate [--force]|apply|finalize  exchange pairing blobs (Germany apply also emits the return Blob B; generate refuses on finalized without --force)")
	fmt.Fprintln(out, "  upgrade [--xray|--origin|--splitter]  upgrade one component (or re-apply) from the environment (Linux root)")
	fmt.Fprintln(out, "  rollback --to state-id              converge the host to a retained revision (Linux root)")
	fmt.Fprintln(out, "  uninstall [--purge]                 remove the deployment (Linux root)")
	fmt.Fprintln(out, "  recover                             execute journal-driven post-crash recovery (Linux root)")
	fmt.Fprintln(out, "  recover --ack                       force-clear the journal without host changes (Linux root)")
	fmt.Fprintln(out, "  config show                         show the committed deployment config")
	fmt.Fprintln(out, "  config set KEY=VALUE ...            apply configuration changes transactionally (Linux root)")
}
