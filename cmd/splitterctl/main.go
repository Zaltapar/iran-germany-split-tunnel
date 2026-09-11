// Command splitterctl is the thin operator-facing deployment entrypoint.
// Deployment policy and state live in internal/deploy; this file only parses
// commands, renders safe output, and maps errors to exit status.
package main

import (
	"context"
	"errors"
	"fmt"
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

func run(ctx context.Context, args []string, out, errOut interface{ Write([]byte) (int, error) }) error {
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
		return status(ctx, store, out)
	case "doctor":
		return doctor(ctx, store, out)
	case "install", "upgrade", "rollback", "uninstall", "config", "pair":
		return fmt.Errorf("%w: %s", errNotWired, strings.Join(args, " "))
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
}

func status(_ context.Context, store *deploy.Store, out interface{ Write([]byte) (int, error) }) error {
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

func doctor(ctx context.Context, store *deploy.Store, out interface{ Write([]byte) (int, error) }) error {
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

func printUsage(out interface{ Write([]byte) (int, error) }) {
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
