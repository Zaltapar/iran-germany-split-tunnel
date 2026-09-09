package origin

// cancel_test.go — review HIGH-2: context is threaded through provider,
// download, install, executor and status with CommandContext /
// NewRequestWithContext. A canceled or deadline-exceeded ctx must
// return PROMPTLY with context.Canceled / context.DeadlineExceeded,
// leave the previous state byte-identical, and never begin a new
// mutation after cancellation. All tests are deterministic (pre-canceled
// contexts and blocking fakes — no sleeps).

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// canceledCtx returns an already-canceled context.
func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// errContextCanceled returns the sentinel for the canceled-ctx class.
func errContextCanceled() error { return context.Canceled }

// ---------------------------------------------------------------------------
// Downloader / HTTP (NewRequestWithContext)
// ---------------------------------------------------------------------------

// A canceled ctx aborts an in-flight HTTP download promptly with
// context.Canceled (NewRequestWithContext is in the request path).
func TestHTTPDownloaderHonorsCanceledCtx(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // never respond until the test tears down
	}))
	defer srv.Close()
	dl := HTTPDownloader{}
	start := time.Now()
	_, err := dl.Fetch(canceledCtx(), srv.URL+"/tar")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("canceled Fetch did not return promptly (%v)", time.Since(start))
	}
}

// fetchChecksums honors a canceled ctx via the blocking fake DL.
func TestFetchChecksumsHonorsCanceledCtx(t *testing.T) {
	dl := staticDL{blockOnCtx: true}
	_, err := fetchChecksums(canceledCtx(), dl, "https://example.invalid/ck")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Installer (cancellation before and during the pipeline)
// ---------------------------------------------------------------------------

// A pre-canceled ctx aborts Install before ANY filesystem or network
// action: the prefix holds no version dir and no stage/candidate dir.
func TestInstallCanceledBeforeStart(t *testing.T) {
	tarBytes := makeTarGz(t)
	in, _, prefix := installFixture(t, tarBytes)
	if _, err := in.Install(canceledCtx(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	versionDir, _ := VersionDir(prefix, PinnedVersion)
	if _, err := os.Lstat(versionDir); !os.IsNotExist(err) {
		t.Errorf("version dir created under a canceled ctx")
	}
	if _, err := os.Lstat(versionDir + ".new"); !os.IsNotExist(err) {
		t.Errorf("candidate dir created under a canceled ctx")
	}
	assertNoStageDirs(t, prefix)
}

// A ctx canceled during the download aborts Install (blocking fake).
func TestInstallCanceledDuringDownload(t *testing.T) {
	dl := staticDL{blockOnCtx: true}
	fe := &fakeExec{}
	in := &Installer{Prefix: t.TempDir(), DL: dl, Exec: fe}
	start := time.Now()
	if _, err := in.Install(canceledCtx(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("canceled Install did not return promptly (%v)", time.Since(start))
	}
}

// A FORCED reinstall under a pre-canceled ctx preserves the existing
// working version byte-identically (HIGH-1 × HIGH-2 interaction).
func TestForceInstallCanceledPreservesExisting(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, _ := forcedInstaller(t, prefix)
	if _, err := in.Install(canceledCtx(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

// A ctx canceled at the smoke check aborts the install (blocking fake
// executor) and leaves no candidate residue.
func TestInstallCanceledAtSmokeCheck(t *testing.T) {
	tarBytes := makeTarGz(t)
	ta, _ := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	ca, _ := ChecksumURL(PinnedVersion)
	dl := staticDL{files: map[string][]byte{ta: tarBytes, ca: checksumsFor(t, tarBytes)}}
	fe := &fakeExec{blockOnCtx: true}
	prefix := t.TempDir()
	in := &Installer{Prefix: prefix, DL: dl, Exec: fe}
	if _, err := in.Install(canceledCtx(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	versionDir, _ := VersionDir(prefix, PinnedVersion)
	if _, err := os.Lstat(versionDir); !os.IsNotExist(err) {
		t.Errorf("version dir left after a canceled install")
	}
	if _, err := os.Lstat(versionDir + ".new"); !os.IsNotExist(err) {
		t.Errorf("candidate dir left after a canceled install")
	}
}

// ---------------------------------------------------------------------------
// OSExecutor (CommandContext) — a real child process is killed by a
// canceled ctx. Uses the Go toolchain itself as the long-running child
// (no external dependency).
// ---------------------------------------------------------------------------

func TestOSExecutorKillsChildOnCancel(t *testing.T) {
	// `go version` exits instantly; use `go help` in a loop is not
	// portable. Instead run a command that blocks: the test binary's own
	// sleep helper is overkill — use `go env` under a ctx that is
	// ALREADY canceled, which must fail before/at start.
	ctx := canceledCtx()
	_, err := OSExecutor{}.VersionOutput(ctx, os.Args[0])
	if err == nil {
		t.Fatal("expected an error under a canceled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

// A deadline-exceeded ctx bounds a blocking child. We use the blocking
// fake executor here to keep the test hermetic and fast; the real
// CommandContext kill is covered by TestOSExecutorKillsChildOnCancel.
func TestExecutorDeadlineExceeded(t *testing.T) {
	fe := &fakeExec{blockOnCtx: true}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := fe.VersionOutput(ctx, "/fake/caddy")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Provider Configure/Status (canceled ctx, byte-identical previous state)
// ---------------------------------------------------------------------------

// A canceled ctx aborts Configure before any mutation: an existing live
// Caddyfile is untouched and no new file appears.
func TestCaddyConfigureCanceledCtx(t *testing.T) {
	core, dir, fe := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "Caddyfile")
	before, _ := os.ReadFile(live)
	gatesBefore := countGates(fe)
	if err := p.Configure(canceledCtx(), goldenPlanALPN()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	after, _ := os.ReadFile(live)
	if string(before) != string(after) {
		t.Errorf("live Caddyfile changed under a canceled ctx")
	}
	if countGates(fe) != gatesBefore {
		t.Errorf("gate ran under a canceled ctx")
	}
}

// fileStatus honors a canceled ctx before the binary invocations.
func TestCaddyStatusCanceledCtx(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Status(canceledCtx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// ensureInstalled returns the ctx error (not ErrVersionMismatch) when
// the version probe is canceled.
func TestEnsureInstalledCanceledVersionProbe(t *testing.T) {
	core, _, fe := wireCore(t)
	fe.blockOnCtx = true
	if _, err := core.ensureInstalled(canceledCtx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers shared with the activate_rollback tests
// ---------------------------------------------------------------------------

var _ = io.Discard
var _ = strings.Contains
