package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// ---------------------------------------------------------------------------
// DEFECT 3 — pairing fingerprint staleness after a config-rotating
// transaction: the committed pairing B-fingerprint must be visible as stale
// (explicit marker + public-param drift) to `doctor`, and a config-rotating
// commit must LEAVE the explicit marker on the committed manifest.
// ---------------------------------------------------------------------------

// Fixed NON-PRODUCTION Reality vectors (the same class of documented test
// vector as internal/xray's keygen/realitypub tests): no deployed key, no
// secret. The public-key half only needs to be 32 valid RawURL bytes for
// checkKeypair; the reader under test DERIVES the public key from the
// private key, so no second real vector is needed.
const (
	pairingTestSNI     = "www.example.org"
	pairingTestShortID = "0123456789abcdef"
	pairingTestUUID    = "550e8400-e29b-41d4-a716-446655440000"
	pairingTestPriv    = "gAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHkA"
)

func pairingTestParams() xray.RealityParams {
	return xray.RealityParams{SNI: pairingTestSNI, ShortID: pairingTestShortID, UUID: pairingTestUUID}
}

// writePairingCheckConfig renders a real Germany config through the
// authoritative generator into a temp file (the installed-config shape the
// doctor check re-derives) and returns its path.
func writePairingCheckConfig(t *testing.T, params xray.RealityParams) string {
	t.Helper()
	out, err := xray.RenderGermanyConfig(params, &xray.Keypair{
		PrivateRaw: pairingTestPriv,
		PublicRaw:  strings.Repeat("A", 43), // 32 zero bytes, RawURL; validation-only
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray-germany.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pairingCheckManifest is a committed Germany deployment whose public
// Reality parameters re-derive to fingerprint fp ("" = no recorded
// fingerprint, the legacy/empty case).
func pairingCheckManifest(store *Store, configPath, fp string) Manifest {
	return Manifest{
		Role:       RoleGermany,
		Generation: "g-pair-check",
		Paths:      Paths{StateRoot: store.Root, Config: configPath},
		Components: Components{Xray: ComponentState{Version: "v26.3.27", RealityFingerprint: fp}},
		Pairing:    PairingState{PeerRole: RoleIran, State: "finalized", Fingerprints: []string{"fp-a", "fp-b"}},
		Firewall:   FirewallState{Backend: "none"},
	}
}

func TestPairingStalenessCheck(t *testing.T) {
	params := pairingTestParams()
	fp := realityFingerprint(params)

	t.Run("no committed manifest is not applicable", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.ID != PairingStalenessCheckID || f.Severity != SeverityPass {
			t.Fatalf("finding = %+v, want pass (not applicable)", f)
		}
	})

	t.Run("iran manifest is not applicable", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		m := pairingCheckManifest(store, writePairingCheckConfig(t, params), fp)
		m.Role = RoleIran
		if _, err := store.Commit(m, "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityPass {
			t.Fatalf("finding = %+v, want pass (Iran carries no Reality config)", f)
		}
	})

	t.Run("germany without a config path is not applicable", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Commit(pairingCheckManifest(store, "", fp), "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityPass {
			t.Fatalf("finding = %+v, want pass (no committed config path)", f)
		}
	})

	t.Run("clean committed params pass", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		config := writePairingCheckConfig(t, params)
		if _, err := store.Commit(pairingCheckManifest(store, config, fp), "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityPass {
			t.Fatalf("finding = %+v, want pass (fingerprint matches the installed config)", f)
		}
	})

	t.Run("stale marker warns with the re-emit action", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		m := pairingCheckManifest(store, writePairingCheckConfig(t, params), fp)
		m.Pairing.PairingStale = true
		if _, err := store.Commit(m, "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityWarn {
			t.Fatalf("finding = %+v, want warn", f)
		}
		for _, want := range []string{"marked the pairing stale", "run pair apply to re-emit"} {
			if !strings.Contains(f.Summary, want) && !strings.Contains(f.Action, want) {
				t.Fatalf("finding = %+v, want it to name %q", f, want)
			}
		}
	})

	t.Run("public-param drift warns", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		// The committed fingerprint was computed from a DIFFERENT public
		// parameter set than the installed config (out-of-band edit).
		drifted := params
		drifted.UUID = "999e8400-e29b-41d4-a716-446655440001"
		m := pairingCheckManifest(store, writePairingCheckConfig(t, params), realityFingerprint(drifted))
		if _, err := store.Commit(m, "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityWarn {
			t.Fatalf("finding = %+v, want warn", f)
		}
		if !strings.Contains(f.Summary, "drifted from the committed fingerprint") {
			t.Fatalf("finding = %+v, want the param-drift reason", f)
		}
		if strings.Contains(f.Summary, "marked the pairing stale") {
			t.Fatalf("finding = %+v, must not claim the marker fired", f)
		}
	})

	t.Run("marker and drift warn with both reasons", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		drifted := params
		drifted.SNI = "drifted.example.org"
		m := pairingCheckManifest(store, writePairingCheckConfig(t, params), realityFingerprint(drifted))
		m.Pairing.PairingStale = true
		if _, err := store.Commit(m, "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityWarn {
			t.Fatalf("finding = %+v, want warn", f)
		}
		if !strings.Contains(f.Summary, "marked the pairing stale") || !strings.Contains(f.Summary, "drifted from the committed fingerprint") {
			t.Fatalf("finding = %+v, want BOTH reasons", f)
		}
	})

	t.Run("corrupt config fails closed", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(t.TempDir(), "xray-germany.json")
		if err := os.WriteFile(config, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Commit(pairingCheckManifest(store, config, fp), "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityFail {
			t.Fatalf("finding = %+v, want fail (the re-derivation is impossible)", f)
		}
		if !strings.Contains(f.Summary, "config shape invalid") {
			t.Fatalf("finding = %+v, want the sentinel class", f)
		}
		// No config bytes or key material may leak into the finding.
		if strings.Contains(f.Summary, "not json") || strings.Contains(f.Summary, pairingTestPriv) {
			t.Fatalf("finding leaked config content: %+v", f)
		}
	})

	t.Run("absent config fails closed", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(t.TempDir(), "removed.json")
		if _, err := store.Commit(pairingCheckManifest(store, config, fp), "test"); err != nil {
			t.Fatal(err)
		}
		f := PairingStalenessCheck(store).Run(context.Background())
		if f.Severity != SeverityFail {
			t.Fatalf("finding = %+v, want fail (committed config is gone)", f)
		}
		if !strings.Contains(f.Summary, "config path unreadable") {
			t.Fatalf("finding = %+v, want the sentinel class", f)
		}
	})
}

// TestPairingStalenessCheckIsReadOnly documents and proves the READ-ONLY
// guarantee: the check re-derives the installed config and the committed
// fingerprint, but the state root and the config file are byte-for-byte
// IDENTICAL afterwards.
func TestPairingStalenessCheckIsReadOnly(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	params := pairingTestParams()
	config := writePairingCheckConfig(t, params)
	m := pairingCheckManifest(store, config, realityFingerprint(params))
	m.Pairing.PairingStale = true
	if _, err := store.Commit(m, "test"); err != nil {
		t.Fatal(err)
	}

	snapshot := func() string {
		sums := map[string]string{}
		for _, root := range []string{store.Root, filepath.Dir(config)} {
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, de := range entries {
				p := filepath.Join(root, de.Name())
				st, err := os.Lstat(p)
				if err != nil {
					t.Fatal(err)
				}
				if st.IsDir() {
					sums[p] = "dir"
					continue
				}
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(b)
				sums[p] = hex.EncodeToString(h[:])
			}
		}
		keys := make([]string, 0, len(sums))
		for k := range sums {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + "|" + sums[k] + "\n")
		}
		return b.String()
	}

	before := snapshot()
	f := PairingStalenessCheck(store).Run(context.Background())
	after := snapshot()
	if before != after {
		t.Fatalf("pairing staleness check MUTATED host state:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if f.Severity != SeverityWarn {
		t.Fatalf("finding = %+v, want warn (marker set, params clean)", f)
	}
}

// TestBuildPairingStalenessFinding pins the pure verdict renderer: every
// fact combination maps to exactly one documented severity and action.
func TestBuildPairingStalenessFinding(t *testing.T) {
	cases := []struct {
		name    string
		facts   pairingStalenessFacts
		err     error
		want    Severity
		summary string
	}{
		{"check error fails closed", pairingStalenessFacts{}, errSentinelForTest, SeverityFail, "pairing staleness check failed"},
		{"not applicable passes", pairingStalenessFacts{applicable: false}, nil, SeverityPass, "not applicable"},
		{"unreadable config fails with the class", pairingStalenessFacts{applicable: true, configErr: errReadForTest}, nil, SeverityFail, "config path unreadable"},
		{"mis-shaped config fails with the class", pairingStalenessFacts{applicable: true, configErr: errShapeForTest}, nil, SeverityFail, "config shape invalid"},
		{"bad key fails with the class", pairingStalenessFacts{applicable: true, configErr: errKeyForTest}, nil, SeverityFail, "installed Reality key failed validation"},
		{"clean facts pass", pairingStalenessFacts{applicable: true}, nil, SeverityPass, "matches the installed Reality config"},
		{"marker alone warns", pairingStalenessFacts{applicable: true, marker: true}, nil, SeverityWarn, "marked the pairing stale"},
		{"param drift alone warns", pairingStalenessFacts{applicable: true, paramDrift: true}, nil, SeverityWarn, "drifted from the committed fingerprint"},
		{"marker and drift warn with both reasons", pairingStalenessFacts{applicable: true, marker: true, paramDrift: true}, nil, SeverityWarn, "stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildPairingStalenessFinding(tc.facts, tc.err)
			if f.ID != PairingStalenessCheckID {
				t.Fatalf("finding id = %q", f.ID)
			}
			if f.Severity != tc.want {
				t.Fatalf("severity = %s, want %s (facts %+v)", f.Severity, tc.want, tc.facts)
			}
			if !strings.Contains(f.Summary, tc.summary) {
				t.Fatalf("summary = %q, want it to contain %q", f.Summary, tc.summary)
			}
			if tc.want == SeverityWarn && !strings.Contains(f.Action, "pair apply") {
				t.Fatalf("warn action = %q, must point at pair apply", f.Action)
			}
		})
	}
}

// errSentinelForTest / errReadForTest / errShapeForTest / errKeyForTest are
// the sentinel errors the renderer must classify without echoing content.
var (
	errSentinelForTest = &sentinelForTest{"check exploded"}
	errReadForTest     = errWrapForTest{sentinel: xray.ErrInstalledConfigRead, detail: "open: no such file"}
	errShapeForTest    = errWrapForTest{sentinel: xray.ErrInstalledConfig, detail: "config is not valid JSON for this shape"}
	errKeyForTest      = errWrapForTest{sentinel: xray.ErrInstalledKey, detail: "privateKey: must decode to 32 bytes"}
)

type sentinelForTest struct{ msg string }

func (e *sentinelForTest) Error() string { return e.msg }

type errWrapForTest struct {
	sentinel error
	detail   string
}

func (e errWrapForTest) Error() string { return e.sentinel.Error() + ": " + e.detail }
func (e errWrapForTest) Unwrap() error { return e.sentinel }

// pairingMarkerFake is an Adapter fake implementing the optional
// PairingStaleMarker capability: it reports a scripted rotation verdict so
// the commit-time marker policy is pinned without a host.
type pairingMarkerFake struct {
	adapterFake
	stale bool
}

func (f *pairingMarkerFake) MarkPairingStale() bool { return f.stale }

// TestCommitRecordsPairingStaleMarker is the transaction-level DEFECT-3
// regression: a commit whose activate rotated the live config must carry the
// explicit pairingStale marker into the committed manifest, and a commit
// without the capability (or without rotation) must NOT. The marker is the
// only record of a rotation — the public-parameter fingerprint is blind to a
// regenerated keypair by design.
func TestCommitRecordsPairingStaleMarker(t *testing.T) {
	newStore := func() *Store {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	desired := func(store *Store) DesiredState {
		return DesiredState{Role: RoleIran, Paths: Paths{StateRoot: store.Root}}
	}

	t.Run("config-rotating commit marks the pairing stale", func(t *testing.T) {
		store := newStore()
		result, err := ApplyDesired(context.Background(), store, Manifest{}, desired(store), &pairingMarkerFake{stale: true})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !result.Changed {
			t.Fatalf("result = %+v, want a committed change", result)
		}
		if !result.Manifest.Pairing.PairingStale {
			t.Fatalf("committed pairing = %+v, want PairingStale=true", result.Manifest.Pairing)
		}
		loaded, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if !loaded.Pairing.PairingStale {
			t.Fatalf("persisted pairing = %+v, want the marker on disk", loaded.Pairing)
		}
	})

	t.Run("unrotated commit leaves the pairing unmarked", func(t *testing.T) {
		store := newStore()
		result, err := ApplyDesired(context.Background(), store, Manifest{}, desired(store), &pairingMarkerFake{stale: false})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if result.Manifest.Pairing.PairingStale {
			t.Fatalf("committed pairing = %+v, a byte-identical activation must not mark stale", result.Manifest.Pairing)
		}
	})

	t.Run("adapter without the capability leaves the pairing unmarked", func(t *testing.T) {
		store := newStore()
		result, err := ApplyDesired(context.Background(), store, Manifest{}, desired(store), &adapterFake{})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if result.Manifest.Pairing.PairingStale {
			t.Fatalf("committed pairing = %+v, want the marker absent (nil capability)", result.Manifest.Pairing)
		}
	})
}

// TestMarkPairingStaleReflectsConfigRotation pins the production adapter
// seam: MarkPairingStale reports exactly whether THIS adapter's Activate
// phase rotated the live Germany config bytes (the xrayConfigChanged flag),
// so a convergent re-apply never marks the pairing stale.
func TestMarkPairingStaleReflectsConfigRotation(t *testing.T) {
	unrotated := newGermanyActivateFixture(t, false)
	if unrotated.adapter.MarkPairingStale() {
		t.Fatal("unactivated adapter must not report a rotation")
	}
	if err := unrotated.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if unrotated.adapter.MarkPairingStale() {
		t.Fatal("a byte-identical activation must not mark the pairing stale")
	}

	rotated := newGermanyActivateFixture(t, true)
	if err := rotated.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !rotated.adapter.MarkPairingStale() {
		t.Fatal("a config-rotating activation must mark the pairing stale")
	}
}
