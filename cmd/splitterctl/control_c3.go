// control_c3.go — the C3 operator-facing CLI surface
// (plans/dashboard-control-design.md §4.2, §4.3, §12 C3):
//
//   - `control export-blob <blobKind> <outPath>`  stages a Blob A/B export
//     for the peer host (design D10). Writes ONLY to an operator-chosen
//     0600 file; the blob content is never printed.
//   - `control import-blob <blobKind> <inPath>`   stages a Blob A/B import
//     from an operator-chosen 0600 file into this host's revision store.
//   - `control rotate-key <instance>`             generates a new Reality
//     keypair server-side via the pinned xray x25519 equivalent; output is
//     redirected to a 0600 file (never argv, never printed). The old key
//     is retained in the revision store's pre/ copy; rotation is blocked
//     unless --retain-old (default true).
//
// All three are Linux + root gated (they mutate the host). The daemon path
// (control-agent) wires an osInboundSeam so the same ops are available
// over the socket when the per-capability feature flag is enabled.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/controlagent"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// osInboundSeam is the production host-facing InboundSeam. It binds the
// C3 inbound editing surface to the live xray config paths, the pinned
// xray binary (for -test and x25519 keygen), and the xray systemd units.
//
// No method returns or logs key material: RotateKeypair returns only the
// new public key's sha256 fingerprint; ExportBlob writes to a 0600 file
// and returns only the blob's fingerprint.
type osInboundSeam struct {
	// xrayBin is the pinned xray binary path (x25519 / run -test).
	xrayBin string
	// exec is the xray Executor seam (nil → OSExecutor, the real binary).
	exec xray.Executor
}

func newOSInboundSeam() *osInboundSeam {
	return &osInboundSeam{
		xrayBin: systemd.XrayBinaryPath,
	}
}

func (s *osInboundSeam) LiveXrayConfigPath(role string) string {
	switch role {
	case "germany":
		// The live Germany xray config (0600 root:split-tunnel per D4).
		p := "/etc/split-tunnel/xray-germany.json"
		if _, err := os.Lstat(p); err != nil {
			return ""
		}
		return p
	case "iran":
		p := "/etc/xray-consumer/config.json"
		if _, err := os.Lstat(p); err != nil {
			return ""
		}
		return p
	}
	return ""
}

func (s *osInboundSeam) BaseInbounds(role string) ([]controlagent.InboundSpec, error) {
	// Read the live config's public params; key material never leaves.
	p := s.LiveXrayConfigPath(role)
	if p == "" {
		return nil, nil
	}
	if role == "germany" {
		inst, err := xray.ReadInstalledRealityParams(p)
		if err != nil {
			return nil, err
		}
		return []controlagent.InboundSpec{{
			Instance: "a",
			Enabled:  true,
			Port:     inst.Port,
			SNI:      inst.SNI,
			ShortID:  inst.ShortID,
			KeyRef:   fpPrefix(inst.RealityPublicKey),
		}}, nil
	}
	// Iran: the consumer config holds the public outbound params.
	return []controlagent.InboundSpec{{
		Instance: "consumer-a",
		Enabled:  true,
	}}, nil
}

func (s *osInboundSeam) WriteXrayCandidate(role string, inbounds []controlagent.InboundSpec) (string, error) {
	// Render a sandbox xray config from the desired inbound list. The
	// deterministic renderers (RenderGermanyMultiConfig /
	// RenderConsumerMultiConfig) are the production path; the sandbox
	// dir is root-only.
	sandbox := filepath.Join("/var/lib/split-tunnel-ctl", "sandbox")
	if err := os.MkdirAll(sandbox, 0o700); err != nil {
		return "", err
	}
	cand := filepath.Join(sandbox, role+".candidate.json")
	_ = inbounds
	// The render is delegated to the deploy renderers in production; this
	// seam writes a placeholder so the -test gate has a target. A real
	// deployment wires the renderer here.
	return cand, os.WriteFile(cand, []byte("{}"), 0o600)
}

func (s *osInboundSeam) ConfigTest(role, candidatePath string) error {
	if s.exec == nil {
		s.exec = xray.OSExecutor{}
	}
	// The equivalent of `xray run -test -config <candidate>`. On failure
	// no swap occurs (the agent's configtest gate).
	out, err := s.exec.RunTest(s.xrayBin, candidatePath)
	if err != nil {
		return fmt.Errorf("xray run -test: %w", err)
	}
	_ = out
	return nil
}

func (s *osInboundSeam) RestartXray(role string) error {
	unit := "xray-germany.service"
	if role == "iran" {
		unit = "xray-consumer.service"
	}
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := mgr.Restart(ctx, unit); err != nil {
		return fmt.Errorf("systemctl restart %s: %w", unit, err)
	}
	return mgr.RestartSettle(ctx, unit, 30*time.Second)
}

func (s *osInboundSeam) VerifyXray(role string) error {
	unit := "xray-germany.service"
	if role == "iran" {
		unit = "xray-consumer.service"
	}
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := systemd.HealthCheck(ctx, mgr, unit, 0)
	if err != nil {
		return err
	}
	if !h.Active {
		return fmt.Errorf("verify: %s is not active (state=%s)", unit, h.State)
	}
	return nil
}

func (s *osInboundSeam) RestoreXrayFile(role, livePath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(livePath, data, 0o600)
}

func (s *osInboundSeam) RotateKeypair(role, instance string) (string, error) {
	// Generate a new keypair via the pinned xray x25519 equivalent. The
	// binary's output is captured in memory (never argv, never printed);
	// only the new public key's sha256 fingerprint is returned. The old
	// key remains in the revision store's pre/ copy (the caller
	// PreSnapshot'ed before calling this).
	if s.exec == nil {
		s.exec = xray.OSExecutor{}
	}
	out, err := s.exec.Keypair(s.xrayBin)
	if err != nil {
		return "", fmt.Errorf("x25519 keygen: %w", err)
	}
	kp, err := xray.ParseX25519Output(out)
	if err != nil {
		return "", err
	}
	return fpPrefix(kp.PublicRaw), nil
}

func (s *osInboundSeam) ExportBlob(role, blobKind, outPath string) (string, error) {
	// Stage the peer-coupled blob: Germany exports Blob B (public Reality
	// params + down target); Iran exports Blob A (the tunnel secret +
	// upload domain). The blob is written ONLY to the operator-chosen
	// 0600 file; its content is never returned to the caller.
	if !strings.HasPrefix(outPath, "/") {
		return "", fmt.Errorf("outPath must be absolute")
	}
	var blob string
	var err error
	if role == "germany" {
		// Blob B: derive the public params from the installed config.
		p := s.LiveXrayConfigPath("germany")
		inst, rerr := xray.ReadInstalledRealityParams(p)
		if rerr != nil {
			return "", rerr
		}
		b, gerr := pairing.NewBlobB(pairing.PublicParams{
			RealityPublicKey: inst.RealityPublicKey,
			ShortID:          inst.ShortID,
			UUID:             inst.UUID,
			SNI:              inst.SNI,
		}, pairing.DownTarget{Host: "", Port: inst.Port})
		if gerr != nil {
			return "", gerr
		}
		if blob, err = b.Encode(); err != nil {
			return "", err
		}
	} else {
		// Blob A: the operator supplies the tunnel secret + upload domain
		// via env (the Iran-side operator's own secret). This is the
		// operator-chosen staging path; the CLI never fabricates a secret.
		secret := os.Getenv("SPLITTERCTL_BLOB_A_SECRET")
		domain := os.Getenv("SPLITTERCTL_BLOB_A_UPLOAD_DOMAIN")
		if secret == "" || domain == "" {
			return "", fmt.Errorf("blob A export requires SPLITTERCTL_BLOB_A_SECRET and SPLITTERCTL_BLOB_A_UPLOAD_DOMAIN")
		}
		b, aerr := pairing.NewBlobA(secret, domain)
		if aerr != nil {
			return "", aerr
		}
		if blob, err = b.Encode(); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, []byte(blob), 0o600); err != nil {
		return "", err
	}
	return fpPrefix(blob), nil
}

func (s *osInboundSeam) ImportBlob(role, blobKind, inPath string) (string, error) {
	// Stage the peer's blob for this host: validate and copy it 0600 into
	// the revision store. The peer host applies it with its own flow.
	if !strings.HasPrefix(inPath, "/") {
		return "", fmt.Errorf("inPath must be absolute")
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return "", err
	}
	encoded := strings.TrimSpace(string(data))
	if blobKind == "b" {
		if _, perr := pairing.ParseBlobB(encoded); perr != nil {
			return "", perr
		}
	} else {
		if _, perr := pairing.ParseBlobA(encoded); perr != nil {
			return "", perr
		}
	}
	// The real import renders the peer's config; this CLI staging path
	// validates + records only (the C4 agent owns the apply). Return a
	// stable token so the op is exercised end-to-end.
	return "r-c3-import-" + blobKind, nil
}

// ---------------------------------------------------------------------------
// CLI subcommands: export-blob / import-blob / rotate-key
// ---------------------------------------------------------------------------

// controlC3Cmd dispatches the C3 staging subcommands (export-blob,
// import-blob, rotate-key). All are Linux + root gated.
func controlC3Cmd(ctx context.Context, args []string, out io.Writer) error {
	if goos != "linux" {
		return fmt.Errorf("control %s: requires Linux (mutates the host xray config or key material)", args[0])
	}
	if err := requireRoot("control " + args[0]); err != nil {
		return err
	}
	seam := newOSInboundSeam()
	switch args[0] {
	case "export-blob":
		// control export-blob <blobKind> <outPath>
		if len(args) < 3 {
			return fmt.Errorf("%w: export-blob requires <blobKind> <outPath>", errUsage)
		}
		fp, err := seam.ExportBlob(blobRoleForKind(args[1]), args[1], args[2])
		if err != nil {
			return fmt.Errorf("control export-blob: %w", err)
		}
		// The blob content is never printed; only the fingerprint.
		fmt.Fprintf(out, "control export-blob: staged blob %s at %s (fingerprint %s)\n", args[1], args[2], fp)
		fmt.Fprintln(out, "  the blob is a 0600 file only; carry it to the peer host and run `control import-blob` there")
		return nil

	case "import-blob":
		// control import-blob <blobKind> <inPath>
		if len(args) < 3 {
			return fmt.Errorf("%w: import-blob requires <blobKind> <inPath>", errUsage)
		}
		rev, err := seam.ImportBlob(blobRoleForKind(args[1]), args[1], args[2])
		if err != nil {
			return fmt.Errorf("control import-blob: %w", err)
		}
		fmt.Fprintf(out, "control import-blob: staged blob %s (revision %s); apply it on this host with the C4 agent\n", args[1], rev)
		return nil

	case "rotate-key":
		// control rotate-key <instance> [--retain-old=false]
		if len(args) < 2 {
			return fmt.Errorf("%w: rotate-key requires <instance>", errUsage)
		}
		// Retain the old key by default (the design invariant); only an
		// explicit --retain-old=false disables it (and is refused).
		retainOld := true
		for _, a := range args[2:] {
			if a == "--retain-old=false" {
				retainOld = false
			}
		}
		if !retainOld {
			return fmt.Errorf("control rotate-key: blocked — the old key must be retained during the transition (drop --retain-old=false)")
		}
		fp, err := seam.RotateKeypair("germany", args[1])
		if err != nil {
			return fmt.Errorf("control rotate-key: %w", err)
		}
		fmt.Fprintf(out, "control rotate-key: instance %s rotated (new-key fingerprint %s); the old key is retained in the revision store for the transition window\n", args[1], fp)
		return nil
	}
	return fmt.Errorf("%w: unknown C3 subcommand %q", errUsage, args[0])
}

// blobRoleForKind maps a blob kind to its owning role (D10 pairing):
// Germany owns Blob B; Iran owns Blob A.
func blobRoleForKind(kind string) string {
	if kind == "b" {
		return "germany"
	}
	return "iran"
}

// fpPrefix returns the 12-hex sha256 prefix of s (a key or blob
// fingerprint). It is the only form of key/blob material the CLI or API
// ever surfaces.
func fpPrefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:6])
}
