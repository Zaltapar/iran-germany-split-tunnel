// Command splitterctl is the thin operator-facing deployment entrypoint.
// Deployment policy and state live in internal/deploy; this file only parses
// commands, renders safe output, and maps errors to exit status.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
)

var errUsage = errors.New("usage error")
var errNotWired = errors.New("command is not wired to host adapters")

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
		return notWired(args)
	case "install":
		if len(args) != 2 || (args[1] != deploy.RoleIran && args[1] != deploy.RoleGermany) {
			return fmt.Errorf("%w: install requires exactly iran or germany", errUsage)
		}
		return notWired(args)
	case "pair":
		if len(args) != 2 || (args[1] != "generate" && args[1] != "apply" && args[1] != "finalize") {
			return fmt.Errorf("%w: pair requires generate, apply, or finalize", errUsage)
		}
		return pairCommand(ctx, store, args[1], out)
	case "upgrade":
		if len(args) > 2 || (len(args) == 2 && !isUpgradeTarget(args[1])) {
			return fmt.Errorf("%w: upgrade accepts at most one of --xray, --origin, or --splitter", errUsage)
		}
		return notWired(args)
	case "rollback":
		if len(args) != 3 || args[1] != "--to" || args[2] == "" || strings.ContainsAny(args[2], `/\\`) {
			return fmt.Errorf("%w: rollback requires --to state-id", errUsage)
		}
		return notWired(args)
	case "uninstall":
		if len(args) > 2 || (len(args) == 2 && args[1] != "--purge") {
			return fmt.Errorf("%w: uninstall accepts only --purge", errUsage)
		}
		return notWired(args)
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
	fmt.Fprintln(out, "usage: splitterctl <install|pair|status|doctor|upgrade|rollback|uninstall|config>")
	fmt.Fprintln(out, "  status                         show persisted deployment state")
	fmt.Fprintln(out, "  doctor                         run read-only deployment checks")
	fmt.Fprintln(out, "  install iran|germany           install a deployment role")
	fmt.Fprintln(out, "  pair generate|apply|finalize   exchange pairing blobs")
	fmt.Fprintln(out, "  upgrade [--xray|--origin|--splitter]")
	fmt.Fprintln(out, "  rollback [--to state-id]")
	fmt.Fprintln(out, "  uninstall [--purge]")
	fmt.Fprintln(out, "  config show|set")
}
