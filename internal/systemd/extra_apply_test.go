// extra_apply_test.go — transactional ApplyExtraUnit (the shared core with
// ApplyUnit): fresh apply, byte-exact no-op, the bin precheck, and
// precheck-driven rollback. Mirrors apply_test.go's L1 harness.
package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// plantExtraPreconditions writes the filesystem artifacts an extra unit's
// bin precheck requires so a fresh apply can proceed past step 1.
func plantExtraPreconditions(t *testing.T, s ExtraUnitSpec) {
	t.Helper()
	// The bin precheck (applyPrecheck) requires BinPath to exist and be
	// regular.
	writeRaw(t, s.BinPath, []byte("fake binary\n"))
}

func TestApplyExtraUnitFreshAndNoop(t *testing.T) {
	for name, s := range extraGoldenSpecs() {
		t.Run(name, func(t *testing.T) {
			redirectPaths(t)
			// Re-root the spec paths at the redirected temp tree (the
			// golden specs carry the canonical /opt and /etc prefixes,
			// which must not be touched by the test).
			s.BinPath = filepath.Join(binaryPrefix, "extra-bin")
			if s.Unit == "tunneldash.service" {
				s.EnvFile = filepath.Join(stateDir, "dashboard.env")
				s.ConfigPath = filepath.Join(stateDir, "dashboard", "config.json")
				writeRaw(t, s.EnvFile, []byte("SPLIT_TUNNELDASH_TOKEN_FILE=/etc/split-tunnel/dashboard/token\n"))
				writeRaw(t, s.ConfigPath, []byte("{}\n"))
			}
			plantExtraPreconditions(t, s)

			live, err := unitPath(s.Unit)
			if err != nil {
				t.Fatal(err)
			}
			ex := &fakeExec{handler: okHandler}
			m := newTestManager(ex)

			// Fresh apply: the transactional core must run the full
			// verify → reload → enable → start → is-active sequence and
			// land the rendered bytes at the live path.
			result, err := ApplyExtraUnit(context.Background(), m, s, nil)
			if err != nil {
				t.Fatalf("ApplyExtraUnit: %v", err)
			}
			if result.Unchanged || !result.Restarted || !result.Health.Active {
				t.Fatalf("fresh result=%+v", result)
			}
			assertCalls(t, ex.calls, []string{
				"systemd-analyze verify " + filepath.Join(filepath.Dir(live), "."+s.Unit+".verify-"+strconv.Itoa(os.Getpid()), s.Unit),
				"systemctl daemon-reload",
				"systemctl enable " + s.Unit,
				"systemctl start " + s.Unit,
				"systemctl is-active " + s.Unit,
			})
			want, _ := RenderExtraUnit(s)
			got, _ := os.ReadFile(live)
			if string(got) != string(want) {
				t.Fatalf("live bytes differ from render:\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}

			// Idempotent no-op: a second apply is byte-exact and makes
			// zero executor calls (§7 test 5).
			oldCalls := len(ex.calls)
			result, err = ApplyExtraUnit(context.Background(), m, s, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Unchanged || len(ex.calls) != oldCalls {
				t.Fatalf("no-op result=%+v calls=%v", result, ex.calls[oldCalls:])
			}
		})
	}
}

// TestApplyExtraUnitBinMissingRefuses verifies the precheck fails closed
// when the ExecStart binary is absent: nothing is written, and no executor
// call is issued.
func TestApplyExtraUnitBinMissingRefuses(t *testing.T) {
	redirectPaths(t)
	s := ExtraUnitSpec{Unit: "xray-consumer.service", BinPath: filepath.Join(binaryPrefix, "missing")}
	ex := &fakeExec{handler: okHandler}
	m := newTestManager(ex)
	_, err := ApplyExtraUnit(context.Background(), m, s, nil)
	if err == nil {
		t.Fatal("expected a precheck refusal for the missing binary")
	}
	if len(ex.calls) != 0 {
		t.Fatalf("executor was called despite a precheck refusal: %v", ex.calls)
	}
}

// TestApplyExtraUnitPrecheckRollback verifies a caller-supplied precheck that
// fails AFTER the bin precheck still refuses before any mutation: the precheck
// runs in the preflight stage, so no candidate is written and no executor is
// called.
func TestApplyExtraUnitPrecheckRefuses(t *testing.T) {
	redirectPaths(t)
	s := ExtraUnitSpec{Unit: "xray-consumer.service", BinPath: filepath.Join(binaryPrefix, "bin")}
	writeRaw(t, s.BinPath, []byte("fake binary\n"))
	ex := &fakeExec{handler: okHandler}
	m := newTestManager(ex)
	sentinel := errors.New("config gate failed")
	_, err := ApplyExtraUnit(context.Background(), m, s, func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the sentinel precheck error, got %v", err)
	}
	if len(ex.calls) != 0 {
		t.Fatalf("executor was called despite a precheck refusal: %v", ex.calls)
	}
}
