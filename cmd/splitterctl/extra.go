// extra.go — the `install-extra` subcommand: provisions the one-click
// installer's additional units (Iran xray-consumer / Germany tunneldash)
// through the transactional ApplyExtraUnit core (internal/systemd).
//
// Design: plans/oneclick-installer-design.md §2 (one-secret flow) and §3
// (dashboard on Germany). The installer's `generate_dashboard` and
// `iran_pair_finalize` steps write the config files; this subcommand
// applies the systemd unit and records it in the manifest.
//
// Environment contracts (errors name fields, never values):
//
//	xray-consumer (Iran):
//	  SPLITTERCTL_CONSUMER_PUBLIC_KEY  base64.RawURLEncoding X25519 public key (from Blob B)
//	  SPLITTERCTL_CONSUMER_SNI         Reality SNI (from Blob B)
//	  SPLITTERCTL_CONSUMER_SHORT_ID    16-hex Reality shortId (from Blob B)
//	  SPLITTERCTL_CONSUMER_UUID        RFC 4122 v4 UUID (from Blob B)
//	  SPLITTERCTL_CONSUMER_DOWN_HOST   Germany down host IP/domain (from Blob B)
//	  SPLITTERCTL_CONSUMER_DOWN_PORT   Germany Reality port (default 443)
//	  SPLITTERCTL_CONSUMER_LISTEN      consumer "addr:port" (default 127.0.0.1:10802)
//	  SPLITTERCTL_XRAY_VERSION         xray version (default PinnedVersion)
//
//	tunneldash (Germany):
//	  SPLITTERCTL_DASH_BASEPATH        32-hex basePath (required)
//	  SPLITTERCTL_DASH_CERT            absolute cert path (required)
//	  SPLITTERCTL_DASH_KEY             absolute key path (required)
//	  SPLITTERCTL_DASH_CONFIG          absolute config.json path (default /etc/split-tunnel/dashboard/config.json)
//	  SPLITTERCTL_DASH_ENVFILE         absolute env file path (default /etc/split-tunnel/dashboard.env)
//	  SPLITTERCTL_DASH_BIN             absolute binary path (default /opt/split-tunnel/tunneldash)

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// Extra-unit env contracts (see file header).
const (
	// SPLITTERCTL_CONSUMER_BLOB_B, when set to an absolute path holding the
	// returned Blob B, is the PREFERRED source of the consumer's public
	// parameters for the installer's one-secret flow (the operator carries
	// Blob B to Iran; the installer hands that exact file here). When set,
	// the individual SPLITTERCTL_CONSUMER_* public-param vars are ignored.
	envConsumerBlobB      = "SPLITTERCTL_CONSUMER_BLOB_B"
	envConsumerPublicKey  = "SPLITTERCTL_CONSUMER_PUBLIC_KEY"
	envConsumerSNI        = "SPLITTERCTL_CONSUMER_SNI"
	envConsumerShortID    = "SPLITTERCTL_CONSUMER_SHORT_ID"
	envConsumerUUID       = "SPLITTERCTL_CONSUMER_UUID"
	envConsumerDownHost   = "SPLITTERCTL_CONSUMER_DOWN_HOST"
	envConsumerDownPort   = "SPLITTERCTL_CONSUMER_DOWN_PORT"
	envConsumerListenAddr = "SPLITTERCTL_CONSUMER_LISTEN"

	envDashBasePath = "SPLITTERCTL_DASH_BASEPATH"
	envDashCert     = "SPLITTERCTL_DASH_CERT"
	envDashKey      = "SPLITTERCTL_DASH_KEY"
	envDashConfig   = "SPLITTERCTL_DASH_CONFIG"
	envDashEnvFile  = "SPLITTERCTL_DASH_ENVFILE"
	envDashBinPath  = "SPLITTERCTL_DASH_BIN"
)

// Canonical extra-unit paths (derived from systemd constants; test-redirectable
// vars are not used here because this is the CLI layer, not the adapter).
const (
	consumerConfigPath = systemd.StateDir + "/xray-consumer.json"
	dashDefaultConfig  = "/etc/split-tunnel/dashboard/config.json"
	dashDefaultEnvFile = "/etc/split-tunnel/dashboard.env"
	dashDefaultBinPath = systemd.BinaryPrefix + "/tunneldash"
	dashTLSDir         = "/etc/split-tunnel/dashboard/tls"
)

// hasExtraUnit reports whether the manifest records the named extra component.
func hasExtraUnit(m deploy.Manifest, component string) bool {
	for _, e := range m.Extra {
		if e.Component == component {
			return true
		}
	}
	return false
}

// installExtraCommand is the `splitterctl install-extra <component>` entrypoint.
// It provisions the installer's additional units through the transactional
// ApplyExtraUnit core. Root-gated; Linux-only; fail-closed.
func installExtraCommand(ctx context.Context, component string, out io.Writer) error {
	if err := requireLinux("install-extra"); err != nil {
		return err
	}
	store, err := canonicalStore()
	if err != nil {
		return err
	}
	manifest, err := store.Load()
	if err != nil {
		return fmt.Errorf("install-extra: load deployment state: %w", err)
	}
	switch component {
	case "xray-consumer":
		return installExtraXrayConsumer(ctx, store, manifest, out)
	case "tunneldash":
		return installExtraTunneldash(ctx, store, manifest, out)
	default:
		return fmt.Errorf("%w: install-extra requires 'xray-consumer' or 'tunneldash'", errUsage)
	}
}

// installExtraXrayConsumer provisions the Iran Xray consumer:
//  1. installs the pinned xray binary (idempotent — converges if present)
//  2. sets the "current" binary pointer
//  3. writes the consumer config (0640 root:split-tunnel)
//  4. applies the xray-consumer.service unit transactionally
//  5. records the unit in the manifest (Manifest.Extra)
func installExtraXrayConsumer(ctx context.Context, store *deploy.Store, manifest deploy.Manifest, out io.Writer) error {
	if manifest.Role != deploy.RoleIran {
		return fmt.Errorf("install-extra: xray-consumer is an Iran component; current role is %q", manifest.Role)
	}

	// Resolve the deterministic consumer parameters: SPLITTERCTL_CONSUMER_BLOB_B
	// (the installer's one-secret flow — the PUBLIC Blob B the operator carried
	// to Iran) takes precedence; otherwise the individual SPLITTERCTL_CONSUMER_*
	// public-param env vars are used. Blob B carries no secret material, so it
	// is safe to read here (only Blob A is the secret carrier).
	params, err := resolveConsumerParams()
	if err != nil {
		return err
	}

	// Render the consumer config (pure function; no I/O).
	cfgBytes, err := xray.RenderConsumerConfig(params)
	if err != nil {
		return fmt.Errorf("install-extra: render consumer config: %w", err)
	}

	// Install xray binary (idempotent — reuses existing version dir).
	xrayVersion := strings.TrimSpace(os.Getenv(envXrayVersion))
	if xrayVersion == "" {
		xrayVersion = xray.PinnedVersion
	}
	arch, err := xray.DefaultArch()
	if err != nil {
		return fmt.Errorf("install-extra: detect arch: %w", err)
	}
	installer := &xray.Installer{Prefix: systemd.BinaryPrefix + "/xray"}
	installed, err := installer.Install(xrayVersion, arch, "")
	if err != nil {
		return fmt.Errorf("install-extra: install xray %s: %w", xrayVersion, err)
	}
	if err := systemd.EnsureBinaryPointer(ctx, systemd.PointerXray, xrayVersion); err != nil {
		return fmt.Errorf("install-extra: xray binary pointer: %w", err)
	}

	// Write the consumer config + converge the state dir.
	if err := writeServiceConfig(consumerConfigPath, cfgBytes); err != nil {
		return fmt.Errorf("install-extra: write %s: %w", consumerConfigPath, err)
	}
	if err := systemd.EnsureStateDir(ctx); err != nil {
		return fmt.Errorf("install-extra: converge state dir: %w", err)
	}

	// Apply the unit transactionally.
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	spec := systemd.ExtraUnitSpec{Unit: "xray-consumer.service", BinPath: systemd.XrayBinaryPath}
	result, err := systemd.ApplyExtraUnit(ctx, mgr, spec, nil)
	if err != nil {
		return fmt.Errorf("install-extra: apply xray-consumer.service: %w", err)
	}

	// Record in manifest.
	unitBytes, _ := systemd.RenderExtraUnit(spec)
	h := sha256.Sum256(unitBytes)
	manifest.Extra = append(manifest.Extra, deploy.ExtraUnitState{
		Unit:       "xray-consumer.service",
		Component:  "xray-consumer",
		Hash:       hex.EncodeToString(h[:]),
		ConfigPath: consumerConfigPath,
	})
	if _, err := store.Commit(manifest, "install-extra xray-consumer"); err != nil {
		return fmt.Errorf("install-extra: commit manifest: %w", err)
	}

	action := "applied"
	if result.Unchanged {
		action = "unchanged"
	}
	_, _ = fmt.Fprintf(out, "install-extra: xray-consumer.service %s\n", action)
	_, _ = fmt.Fprintf(out, "  xray: %s (pointer: %s)\n", installed.Version, systemd.XrayBinaryPath)
	_, _ = fmt.Fprintf(out, "  config: %s (listen %s:%d -> %s:%d)\n", consumerConfigPath, params.ListenAddr, params.ListenPort, params.DownHost, params.DownPort)
	return nil
}

// installExtraTunneldash provisions the Germany dashboard unit:
//  1. verifies the binary + config + env file exist
//  2. converges the TLS dir ownership (0750 root:split-tunnel)
//  3. applies the tunneldash.service unit transactionally
//  4. records the unit in the manifest (Manifest.Extra)
func installExtraTunneldash(ctx context.Context, store *deploy.Store, manifest deploy.Manifest, out io.Writer) error {
	if manifest.Role != deploy.RoleGermany {
		return fmt.Errorf("install-extra: tunneldash is a Germany component; current role is %q", manifest.Role)
	}

	basePath := strings.TrimSpace(os.Getenv(envDashBasePath))
	certPath := strings.TrimSpace(os.Getenv(envDashCert))
	keyPath := strings.TrimSpace(os.Getenv(envDashKey))
	configPath := strings.TrimSpace(os.Getenv(envDashConfig))
	if configPath == "" {
		configPath = dashDefaultConfig
	}
	envFile := strings.TrimSpace(os.Getenv(envDashEnvFile))
	if envFile == "" {
		envFile = dashDefaultEnvFile
	}
	binPath := strings.TrimSpace(os.Getenv(envDashBinPath))
	if binPath == "" {
		binPath = dashDefaultBinPath
	}

	var missing []string
	if basePath == "" {
		missing = append(missing, envDashBasePath)
	}
	if certPath == "" {
		missing = append(missing, envDashCert)
	}
	if keyPath == "" {
		missing = append(missing, envDashKey)
	}
	if len(missing) > 0 {
		return fmt.Errorf("install-extra: tunneldash requires %s", strings.Join(missing, ", "))
	}

	// Verify the required files exist before any mutation.
	for _, f := range []string{binPath, configPath, envFile} {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("install-extra: %s is missing or not a regular file (write it first)", f)
		}
	}

	// Converge the TLS dir ownership (0750 root:split-tunnel).
	if err := systemd.ConvergeRootGroup(ctx, dashTLSDir, 0o750); err != nil {
		return fmt.Errorf("install-extra: converge TLS dir: %w", err)
	}

	// Apply the unit transactionally.
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	spec := systemd.ExtraUnitSpec{
		Unit:       "tunneldash.service",
		BinPath:    binPath,
		BasePath:   basePath,
		EnvFile:    envFile,
		ConfigPath: configPath,
	}
	result, err := systemd.ApplyExtraUnit(ctx, mgr, spec, nil)
	if err != nil {
		return fmt.Errorf("install-extra: apply tunneldash.service: %w", err)
	}

	// Record in manifest.
	unitBytes, _ := systemd.RenderExtraUnit(spec)
	h := sha256.Sum256(unitBytes)
	manifest.Extra = append(manifest.Extra, deploy.ExtraUnitState{
		Unit:       "tunneldash.service",
		Component:  "tunneldash",
		Hash:       hex.EncodeToString(h[:]),
		ConfigPath: configPath,
		EnvFile:    envFile,
		BasePath:   basePath,
	})
	if _, err := store.Commit(manifest, "install-extra tunneldash"); err != nil {
		return fmt.Errorf("install-extra: commit manifest: %w", err)
	}

	action := "applied"
	if result.Unchanged {
		action = "unchanged"
	}
	// Secret hygiene: the basePath is the 32-hex first-access secret. It is
	// embedded in the dashboard config and the rendered unit's env wiring, and
	// the operator can recover it from /etc/split-tunnel/dashboard/config.json
	// (0640). It is never echoed here — this command's output stays
	// secret-free (field names only), matching the installer's contract.
	_, _ = fmt.Fprintf(out, "install-extra: tunneldash.service %s\n", action)
	_, _ = fmt.Fprintf(out, "  dashboard reachable only via TLS at a random basePath (read it from %s; never printed here)\n", configPath)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeServiceConfig writes a service-readable config file atomically
// (0640 root:split-tunnel on Linux; 0644 elsewhere for dev). The parent
// directory is created if needed. The write is crash-safe: tmp + fsync +
// rename. On Linux, ownership is converged by a subsequent EnsureStateDir
// call (which is the D4 pattern: secrets are 0600 root:root; service-readable
// configs are 0640 root:split-tunnel).
func writeServiceConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	mode := os.FileMode(0o644)
	if runtime.GOOS == "linux" {
		mode = 0o640
	}
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create temp %s: %w", tmp, err)
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	ok = true
	return nil
}

// parseListenAddr parses "host:port" with sensible defaults. On parse error
// it falls back to the provided defaults rather than failing — the caller
// (installExtraXrayConsumer) has already validated the required fields.
func parseListenAddr(raw string, defHost string, defPort int) (string, int) {
	if raw == "" {
		return defHost, defPort
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return defHost, defPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return defHost, defPort
	}
	return host, port
}

// resolveConsumerParams returns the deterministic consumer parameters from
// either SPLITTERCTL_CONSUMER_BLOB_B (the installer's one-secret flow: the
// PUBLIC Blob B carried to Iran; the PREFERRED source) or the individual
// SPLITTERCTL_CONSUMER_* public-param env vars. Errors name fields, never
// values.
func resolveConsumerParams() (xray.ConsumerParams, error) {
	if blobPath := strings.TrimSpace(os.Getenv(envConsumerBlobB)); blobPath != "" {
		if !filepath.IsAbs(blobPath) {
			return xray.ConsumerParams{}, fmt.Errorf("install-extra: %s must be an absolute path", envConsumerBlobB)
		}
		data, err := os.ReadFile(blobPath)
		if err != nil {
			return xray.ConsumerParams{}, fmt.Errorf("install-extra: read %s: %w", envConsumerBlobB, err)
		}
		blobB, err := pairing.ParseBlobB(strings.TrimSpace(string(data)))
		if err != nil {
			return xray.ConsumerParams{}, fmt.Errorf("install-extra: parse %s: %w", envConsumerBlobB, err)
		}
		listenAddr, listenPort := parseListenAddr(os.Getenv(envConsumerListenAddr), "127.0.0.1", 10802)
		p := xray.ConsumerParams{
			PublicKey:  blobB.Public.RealityPublicKey,
			SNI:        blobB.Public.SNI,
			ShortID:    blobB.Public.ShortID,
			UUID:       blobB.Public.UUID,
			DownHost:   blobB.Germany.Host,
			DownPort:   blobB.Germany.Port,
			ListenAddr: listenAddr,
			ListenPort: listenPort,
		}
		if err := xray.ValidateConsumerParams(p); err != nil {
			return xray.ConsumerParams{}, fmt.Errorf("install-extra: consumer params from %s: %w", envConsumerBlobB, err)
		}
		return p, nil
	}

	// Env-var path (individual public params).
	pubKey := strings.TrimSpace(os.Getenv(envConsumerPublicKey))
	sni := strings.TrimSpace(os.Getenv(envConsumerSNI))
	shortID := strings.TrimSpace(os.Getenv(envConsumerShortID))
	uuid := strings.TrimSpace(os.Getenv(envConsumerUUID))
	downHost := strings.TrimSpace(os.Getenv(envConsumerDownHost))
	var missing []string
	for name, val := range map[string]string{
		envConsumerPublicKey: pubKey,
		envConsumerSNI:       sni,
		envConsumerShortID:   shortID,
		envConsumerUUID:      uuid,
		envConsumerDownHost:  downHost,
	} {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return xray.ConsumerParams{}, fmt.Errorf("install-extra: xray-consumer requires %s (or %s)",
			strings.Join(missing, ", "), envConsumerBlobB)
	}
	downPort := 443
	if p := strings.TrimSpace(os.Getenv(envConsumerDownPort)); p != "" {
		var err error
		downPort, err = strconv.Atoi(p)
		if err != nil || downPort < 1 || downPort > 65535 {
			return xray.ConsumerParams{}, fmt.Errorf("install-extra: %s must be a port 1..65535", envConsumerDownPort)
		}
	}
	listenAddr, listenPort := parseListenAddr(os.Getenv(envConsumerListenAddr), "127.0.0.1", 10802)
	return xray.ConsumerParams{
		PublicKey:  pubKey,
		SNI:        sni,
		ShortID:    shortID,
		UUID:       uuid,
		DownHost:   downHost,
		DownPort:   downPort,
		ListenAddr: listenAddr,
		ListenPort: listenPort,
	}, nil
}

// writeConsumerConfigFromBlobB renders + writes the consumer config from a
// parsed Blob B (the public params + down target). Called by pairCommand on
// Iran after `pair finalize` succeeds, when the manifest records an
// xray-consumer extra unit. The config is written 0640 (Linux) / 0644 (dev).
// If xray-consumer.service is currently active it is restarted so the new
// config takes effect.
func writeConsumerConfigFromBlobB(ctx context.Context, blobB *pairing.BlobB, out io.Writer) error {
	listenAddr, listenPort := parseListenAddr(os.Getenv(envConsumerListenAddr), "127.0.0.1", 10802)

	params := xray.ConsumerParams{
		PublicKey:  blobB.Public.RealityPublicKey,
		SNI:        blobB.Public.SNI,
		ShortID:    blobB.Public.ShortID,
		UUID:       blobB.Public.UUID,
		DownHost:   blobB.Germany.Host,
		DownPort:   blobB.Germany.Port,
		ListenAddr: listenAddr,
		ListenPort: listenPort,
	}
	cfgBytes, err := xray.RenderConsumerConfig(params)
	if err != nil {
		return fmt.Errorf("pair finalize: render consumer config: %w", err)
	}
	if err := writeServiceConfig(consumerConfigPath, cfgBytes); err != nil {
		return fmt.Errorf("pair finalize: write %s: %w", consumerConfigPath, err)
	}
	if err := systemd.EnsureStateDir(ctx); err != nil {
		return fmt.Errorf("pair finalize: converge state dir: %w", err)
	}

	// Restart xray-consumer if it is active (pick up the new config).
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	if st, _ := mgr.State(ctx, "xray-consumer.service"); st == "active" || st == "activating" {
		if err := mgr.Restart(ctx, "xray-consumer.service"); err != nil {
			_, _ = fmt.Fprintf(out, "pair finalize: warning: restart xray-consumer.service: %v\n", err)
		}
	}
	_, _ = fmt.Fprintln(out, "pair finalize: consumer config written to "+consumerConfigPath)
	return nil
}
