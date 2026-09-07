# ARCHITECT review — T2 `internal/xray` (Xray-core installer)

Reviewer: ARCHITECT mode · Scope: staged, not-yet-committed T2 surface
(`version.go`, `dgst.go`, `http.go`, `install.go`, `install_test.go`,
`pin_test.go`). Companion to `docs/self-contained-deployment-architecture.md`
§4 (managed-transport adapter) and the project engineering rules
(`.roo/rules/tunnel-rules.md`).

## Verdict

**CRITICAL: 0 · HIGH: 0 · MEDIUM: 2 · LOW: 2**

Gate result: **PASS with remediation** — no finding invalidates the design or
violates a hard constraint (engine untouched, Xray reused as a pinned
`.dgst`-verified binary, product/deployment boundary intact, zero new Go
deps). The two MEDIUM items are T2-scope quality defects (failure
containment + gate diagnosability) and are fixed in the same task before
commit, per the CODE → tests → ARCHITECT → fix → tests loop.

## What was checked and confirmed sound

- **Boundary & dependencies.** `internal/xray` imports stdlib only
  (`archive/zip`, `crypto/sha256`, `crypto/subtle`, `net/http`, `os/exec`,
  …). No `pkg/*` import; no new external Go module. Satisfies the §2.2
  invariant and "no unnecessary dependencies".
- **Supply chain (§4.2 pin floor).** Single `PinnedVersion` constant
  (never "latest"); `ValidVersion` is stable-only (`^v\d+\.\d+\.\d+$`,
  prereleases rejected — [version.go:39](../../internal/xray/version.go#L39));
  verification is the upstream-published `.dgst` SHA-256, compared in
  **constant time** ([dgst.go:59](../../internal/xray/dgst.go#L59));
  fail-closed on empty / no-SHA2-256 / malformed digest
  ([dgst.go:30-39](../../internal/xray/dgst.go#L30)).
- **Asset naming.** `Xray-linux-64.zip` (not `-amd64`), `-arm64-v8a`,
  `-arm32-v7a`, `-linux-32` — matches the official XTLS release asset names;
  `.dgst` sidecar is `<zip>.dgst` ([version.go:67-94](../../internal/xray/version.go#L67)).
- **Zip safety.** Traversal is rejected on the **raw** entry name before any
  `filepath.Clean` (which would silently fold `/../x` into `/x`)
  ([install.go:388-407](../../internal/xray/install.go#L388)); size caps are on
  **actual copied bytes** via `io.LimitReader`, not the under-declarable
  `UncompressedSize64` ([install.go:359-368](../../internal/xray/install.go#L359));
  symlink entries are flattened to a text file (no real symlink is created, so
  a `xray -> /etc/passwd` entry cannot redirect the smoke check); the archive
  must contain the `xray` binary or extraction fails
  ([install.go:371](../../internal/xray/install.go#L371)).
- **Atomicity & rollback.** Staging dir is created **inside the prefix**
  (`.xray-stage-*`) so the stage→version move is a same-filesystem atomic
  rename on Linux; a `copyTree` fallback covers exotic cross-device setups;
  stale stage dirs are swept (prefix-scoped); on any post-verify failure the
  staged/version dir is removed and a previously installed version is left
  untouched — which *is* the rollback guarantee
  ([install.go:197-244](../../internal/xray/install.go#L197)).
- **Service safety.** The `xray run -test` gate aborts **before** any service
  (re)start; `RemoveVersion` refuses to delete outside the prefix
  ([install.go:278-295](../../internal/xray/install.go#L278)).
- **Secrets.** No secret material passes through this package; error strings
  never echo zip bytes or config contents.

## Findings

### M1 — chmod failure after rename leaves a poisoned version dir (fix now)

[install.go:245-248](../../internal/xray/install.go#L245):

```go
bin := filepath.Join(versionDir, "xray")
if err := os.Chmod(bin, 0o755); err != nil {
    return nil, fmt.Errorf("xray: chmod: %w", err)
}
```

This runs **after** the rename has already placed `versionDir` in the versioned
layout. A chmod failure (read-only fs, ENOSPC on metadata, EPERM) returns an
error **without** `cleanupVersionDir(versionDir)`, leaving a half-configured
`vX.Y.Z/` whose binary is not executable. The next install is then refused
without `Force` ([install.go:228-231](../../internal/xray/install.go#L228)), so
the prefix is stuck. This breaks the documented invariant "on ANY failure after
step 4 the staged/version dir is removed" and the expectation encoded in
`TestInstallFailureLeavesNoPartialState`.

**Fix:** call `cleanupVersionDir(versionDir)` on the chmod-failure path,
matching the smoke-check and config-gate paths.

### M2 — `run -test` gate discards the diagnostic output (fix now)

[install.go:95-104](../../internal/xray/install.go#L95) `runCombined` returns
`("", err)` on a non-zero exit, so the config gate
([install.go:259-264](../../internal/xray/install.go#L259)) surfaces only
`xray: exit status 1`. The operator cannot see *why* the generated config was
rejected — which directly undercuts design §19.7 (the installer/`doctor` must
distinguish Reality misconfiguration from tunnel-secret vs network failure) and
makes the whole "self-contained, operator never writes Xray JSON" promise hard
to use when generation is wrong.

**Fix:** have `runCombined` return the combined output on error too; surface a
**length-bounded** excerpt (the generated config carries only *public* Reality
parameters — public key, UUID, SNI, dest — and never the tunnel secret or the
Reality private key, so a bounded echo is not a secret leak) in both the
config-gate and smoke-check errors. While here, stop the smoke-check error from
rendering `%!v(<nil>)` when `err == nil` but the output lacks "Xray"
([install.go:254](../../internal/xray/install.go#L254)).

### L1 — unbounded `.dgst` read (hygiene, fix now — one line)

[install.go:177](../../internal/xray/install.go#L177) `io.ReadAll(dgstBody)` has
no size bound. The `.dgst` comes from the same trusted release host as the zip
(whose download is bounded), so risk is low, but it is trivial to make it
fail-closed: read via `io.LimitReader(dgstBody, 1<<20)` and reject an
over-long sidecar.

### L2 — zip entry over the cap is truncated, not rejected (accepted, tracked)

[install.go:359-368](../../internal/xray/install.go#L359): a hostile entry that
**under-declares** `UncompressedSize64` but actually inflates past
`maxSingleEntryBytes` is silently truncated to the cap (the declared-size check
at line 342 already rejects honest oversize entries). This is not a disk-
overflow (both per-entry and total are hard-capped) and the `xray version`
smoke check will fail on a truncated binary, aborting + cleaning up — so it is
fail-later rather than fail-fast. **Accepted** as defense-in-depth; no change
required for v1.

## Acceptance criteria for the remediation commit

1. M1: chmod failure removes `versionDir`; no partial dir, old version
   untouched (extend the failure-containment tests).
2. M2: config-gate and smoke-check errors include a bounded xray output
   excerpt; no `%!v(<nil>)`; a test asserts the excerpt is present and bounded.
3. L1: over-long `.dgst` is rejected.
4. All existing 18 tests remain green; `go vet` clean; Linux `-race` gate green
   before the PR is marked mergeable (never claimed without the actual run).
5. Pin `v26.3.27` is confirmed resolvable by `TestPinnedReleaseAssetsExist` in
   the networked CI run (the L2 pin floor).

**Next:** CODE mode applies M1/M2/L1 + tests → re-run suite → return here for a
confirming re-review → commit → PR → merge.
