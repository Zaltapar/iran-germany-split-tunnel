# T8 Pre-Implementation Audit / Design Checkpoint

**Status:** audit/design checkpoint for milestone 1. Read-only investigation; no features implemented.
**Repository (source of truth):** `c:/Users/Mahdi Fallahnejhad/OneDrive/Documents/Vibe Coding/getting to know CLINE/newTunnel/iran-germany-split-tunnel`
**Remote:** https://github.com/Zaltapar/iran-germany-split-tunnel
**Audit method:** two independent passes (forensic evidence-gathering; adversarial verification). All factual claims cite `file:line` or command evidence. Uncertainty is labelled. Confidence levels are HIGH / MEDIUM / LOW.

> **Repo-progression notice:** the repository has progressed beyond the parent orchestrator's context snapshot. The parent's claim that T8 mutation commands are "only PARSED, not wired" is **stale**: install / rollback / uninstall / recover are now wired to real execution (commits `ac573c6`, `8432962`, `10b4b84`), and a prior checkpoint [`plans/t8b-architecture-checkpoint.md`](plans/t8b-architecture-checkpoint.md:1) already exists. This document supersedes that snapshot where they differ.

---

## 1) Git state

| Check | Command | Result |
|---|---|---|
| Local HEAD | `git rev-parse HEAD` | `67044df259ac019e000202a80ff78490039c77cb` |
| origin/main | `git rev-parse origin/main` | `67044df259ac019e000202a80ff78490039c77cb` (equal) |
| Ahead/behind | `git rev-list --left-right --count origin/main...HEAD` | `0 0` |
| Working tree | `git status --porcelain` | empty (clean) |
| Branches | `git branch -a` | `main`, `feat/t5-systemd`, `l5-harness` (+ remotes) |

**Local == remote. Tree clean.** The L5 acceptance work lives on `l5-harness` (present locally and on origin), not on `main`.

**Recent history (newest first), with phase boundaries:**

```
67044df Document T8-B CLI mutation contract and journal recovery lifecycle   <- T8-B (HEAD)
ac573c6 Wire real splitterctl mutations for install, rollback, uninstall, and recover   <- T8-B
8432962 Reconcile adapter and controller with bounded restore and journal lifecycle     <- T8-B
10b4b84 Add ownership-scoped artifact journal foundation                                <- T8-B
f97013c Wire safe splitterctl pairing commands                                          <- T8-B
bf1bcda Add concrete Linux deployment adapter                                           <- T8-B
faf0a3c Harden Reality inputs and planner drift detection                               <- T8-B
bdc7d28 Complete desired-state convergence projections                                  <- T8-B
5dfd7ab Define explicit fresh-install recovery semantics                                <- T8-B
e7143b3 Add pure systemd deployment handoff plan                                        <- T8-B
f3e0c92 Bridge install requests into deployment controller                              <- T8-B
309faeb Harden deployment request env projection                                        <- T8-B
0c392e3 Add strict splitterctl mutation parsing                                         <- T8-B
fd1ba0c Add validated deployment request boundary                                       <- T8-B
2edfefd Add deployment controller boundary                                              <- T8-B
9da3892 Add typed deployment adapter composition boundary                               <- T8-B
c40fbc4 Add guarded deployment revision rollback                                        <- T8-B
3426320 Harden splitterctl read-only configuration commands                             <- T8-B
871490f Add splitterctl status and doctor scaffold                                      <- T8-B
f127f96 feat: add deployment transactions diagnostics and pairing                       <- T8-B
984cc29 feat: add deployment state and planner                                          <- T8-B
4833f7b feat: add managed firewall boundary                                             <- T8/T6
3a644d0 docs: record resolved budget CI blocker
2b88b42 fix: prevent aggregate buffer waiter starvation
77ee5cb docs: design T8 deployment orchestration
e922907 docs: correct stale design status (T0-T5 implemented @ 457823e)
457823e docs: record T5 merge (906c340) + green CI run #53 in implementation status
906c340 Merge T5: transactional systemd service management                              <- T5 merged
f57d9a8 fix(CI): Linux env fixtures 0600 + isolated symlink tests; bound 200-session stress drain
a454c8c T5: add transactional systemd service management                                 <- T5
dd0ba82 T5: approved design + scoped .gitattributes (eol=lf for byte-pinned assets)      <- T5
f0b44a2 Merge T4: origin/Caddy provider (pinned TLS origin, CDN sub-modes, crash-safe install)  <- T4 merged
83d95ec origin: harden T4 per architect review (rounds 1-3; gate PASS 0/0/0)
f35337d fix(origin): Caddyfile render — single newline before site close; goldens byte-verified on pinned caddy
eda8287 feat(origin): T4 Caddy provider (Caddyfile gen, ACME mode, install) + none/cdn + TLS1.3 preflight  <- T4
2e2da9a docs: record T3 Reality keygen + Germany Xray config merge (PR #26)
1b44347 Merge pull request #26 from Zaltapar/feat/t3-reality-config                        <- T3 merged
8be982f ci(xray): Pinned Xray gate - create production log dir with sudo (runner is non-root)
dee59c2 fix(xray): CRITICAL-2 - Germany outbound freedom+redirect (dokodome-door is inbound-only at v26.3.27)
8d9849d feat(xray): T3 Reality keygen + Germany Xray config generation + -test gate        <- T3
```

---

## 2) T8 actual progress vs parent context claims (delta)

| Parent-context claim | Reality in repo | Verdict |
|---|---|---|
| T8 foundation implemented in `internal/deploy` | Confirmed: state, planner, journal, transaction, controller, adapter, request, diagnostics, systemd plan, rollback | **REAL** |
| Persistent tamper-evident state, atomic writes, revision retention | Confirmed: [`state.go`](internal/deploy/state.go:1); SHA-256 `manifestHash` [`state.go:213`](internal/deploy/state.go:213); `atomicWrite` [`state.go:236`](internal/deploy/state.go:236); `maxRevisions = 10` [`state.go:23`](internal/deploy/state.go:23) | **REAL** |
| Planner / diagnostics / transaction coordinator | Confirmed: [`planner.go`](internal/deploy/planner.go:1), [`diagnostics.go`](internal/deploy/diagnostics.go:1), [`transaction.go`](internal/deploy/transaction.go:1) | **REAL** |
| Typed Adapter interface | Confirmed: 9 methods [`adapter.go:9`](internal/deploy/adapter.go:9) | **REAL** |
| DeploymentController + InstallRequest validation | Confirmed: [`controller.go:14`](internal/deploy/controller.go:14), [`request.go:46`](internal/deploy/request.go:46) | **REAL** |
| Concrete Linux adapter | **PRESENT** (parent did not know this): `LinuxAdapter` [`linux_adapter.go:21`](internal/deploy/linux_adapter.go:21), `NewLinuxAdapter` [`linux_adapter.go:48`](internal/deploy/linux_adapter.go:48), all 9 methods implemented | **REAL (new since parent snapshot)** |
| cmd/splitterctl mutations "only PARSED, not wired" | **STALE.** `install`/`rollback`/`uninstall`/`recover` are wired to real execution; only `config set` and `upgrade` remain `errNotWired` | **PARTIAL / parent stale** |
| T8 PRODUCTION DEPLOYMENT not complete | Confirmed: [`IMPLEMENTATION_STATUS.md:27`](IMPLEMENTATION_STATUS.md:27) states T8 is NOT claimed complete without a clean-Ubuntu L5 acceptance run | **REAL** |
| No concrete adapters previously | Superseded: one concrete adapter exists; there are no separate Iran/Germany adapters (single adapter branches on role) | **REAL (new)** |

**Precise delta:** the T8 *foundation* plus a *first concrete adapter* and *real CLI mutation wiring* now exist. What remains is (a) post-crash recovery runnability, (b) journal persistence of the actual created-set, (c) `DesiredState` convergence completeness, (d) `config set` / `upgrade`, and (e) L5 acceptance on clean hosts. See sections 3–5 and 7.

---

## 3) ISSUE A verdict — fresh-install recovery semantics

**Parent hypothesis:** a fresh-install recovery path calls `Recover(previous Manifest)` where `previous` may be EMPTY, treating `Restore(empty manifest)` as safe fresh-install cleanup.

**VERDICT: DOES NOT EXIST as described. Confidence: HIGH.**

The hypothesis has two parts; only one is factually true:

1. *"`Recover` is called with a possibly-empty `previous`"* — **TRUE.** [`controller.go:58`](internal/deploy/controller.go:58)–[`65`](internal/deploy/controller.go:65) tolerates `os.ErrNotExist` and leaves `previous` as zero `Manifest{}`, then `Transaction.fail` calls `t.Recover(recoveryCtx, t.Previous)` ([`transaction.go:143`](internal/deploy/transaction.go:143)).
2. *"`Restore(empty)` is treated as safe fresh-install cleanup"* — **FALSE**, blocked by two independent defenses:
   - `ApplyDesired`'s recovery closure branches on emptiness ([`adapter.go:43`](internal/deploy/adapter.go:43)):
     ```go
     Recover: func(recoveryCtx context.Context, old Manifest) error {
         if old.Generation == "" {
             return adapter.CleanupFresh(recoveryCtx, desired)
         }
         return adapter.Restore(recoveryCtx, old)
     },
     ```
   - `LinuxAdapter.Restore` explicitly refuses an empty manifest ([`linux_adapter.go:317`](internal/deploy/linux_adapter.go:317)):
     ```go
     if previous.Generation == "" {
         return fmt.Errorf("deploy: LinuxAdapter restore requires a previous committed generation; a fresh install must use CleanupFresh")
     }
     ```

Pinned by tests: [`adapter_test.go:81`](internal/deploy/adapter_test.go:81) (`TestApplyDesiredFreshFailureUsesExplicitCleanup`), [`adapter_test.go:99`](internal/deploy/adapter_test.go:99) (`TestApplyDesiredFreshCleanupFailureIsFatal`), [`linux_adapter_test.go:38`](internal/deploy/linux_adapter_test.go:38) (empty-restore refusal), [`transaction_test.go:224`](internal/deploy/transaction_test.go:224) (journal retained on adapter failure).

**Dedicated fresh-install cleanup semantics EXIST (in-process).** `CleanupFresh` ([`linux_adapter.go:538`](internal/deploy/linux_adapter.go:538)) removes: applied firewall snapshot → reverse-order `RemoveUnit` → in-flight files not in `PreFiles` → xray `current` pointer + `XrayDir` / `OriginDir` → env file.

### 3.1 The real gaps (not the hypothesised one)

**RF-1 / GAP A1 (HIGH) — no post-crash recovery entrypoint; operator deadlocked.**
Repo-wide search for `func .*Recover` finds **only test functions**; the sole production `Recover(` call site is [`transaction.go:143`](internal/deploy/transaction.go:143). `Controller` exposes `Previous`, `ApplyRequest`, `Rollback`, `Uninstall`, `StaleJournal` — **no `Recover`** ([`controller.go:14`](internal/deploy/controller.go:14)). `splitterctl recover` **reports** the journal and, with `--ack`, **deletes** it ([`main.go:345`](cmd/splitterctl/main.go:345)); it never calls `CleanupFresh`/`Restore`. After a hard crash the journal is retained ([`transaction.go:87`](internal/deploy/transaction.go:87)) and the operator is **deadlocked by design**: `install` refuses ([`controller.go:46`](internal/deploy/controller.go:46)), `rollback` refuses ([`controller.go:79`](internal/deploy/controller.go:79)), `uninstall` refuses because no manifest was committed ([`controller.go:100`](internal/deploy/controller.go:100)). Only exit: manual host cleanup + `recover --ack`.

**RF-2 / GAP A2 (HIGH) — recovery depends on runtime-only in-memory sets.**
`CleanupFresh`/`Restore` read `a.units`, `a.inFlightFiles`, `a.firewallApplied` ([`linux_adapter.go:41`](internal/deploy/linux_adapter.go:41), [`544`](internal/deploy/linux_adapter.go:544), [`560`](internal/deploy/linux_adapter.go:560)) — declared "runtime only; never persisted". The persisted [`ArtifactJournal`](internal/deploy/journal.go:26) carries `Files`/`PreFiles`/`Units`/`PreUnits`, but recovery **never reads** `j.Files`, `j.Units`, `j.PreUnits`. `BuildJournal` ([`linux_adapter.go:91`](internal/deploy/linux_adapter.go:91)) records *intended/pre-state* sets, not the *actual created-by-this-transaction* set. Post-crash recovery would therefore operate on empty sets.

**RF-3 / GAP A3 (HIGH) — `os.RemoveAll` on unvalidated journal fields.**
`ArtifactJournal.validate()` ([`journal.go:38`](internal/deploy/journal.go:38)) containment-checks `Files`/`PreFiles` ([`journal.go:42`](internal/deploy/journal.go:42)) and unit-name shape ([`journal.go:47`](internal/deploy/journal.go:47)), but **never validates `XrayDir`/`OriginDir`** — yet `CleanupFresh` executes `os.RemoveAll(j.XrayDir)` ([`linux_adapter.go:577`](internal/deploy/linux_adapter.go:577)) and `os.RemoveAll(j.OriginDir)` ([`linux_adapter.go:583`](internal/deploy/linux_adapter.go:583)). A tampered/corrupt `journal.json` with `"xrayDir":"/etc"` would pass validation. Reachability is constrained (normally overwritten before mutation), but a destructive `RemoveAll` on an unvalidated persisted field is a genuine red flag.
*Sub-claim REFUTED:* `units-backup` is [`StateDir + "/units-backup"`](internal/systemd/systemd.go:78) = `/etc/split-tunnel/units-backup`, i.e. **inside** the state root — not outside containment. Unit files themselves live at [`UnitDir = "/etc/systemd/system"`](internal/systemd/systemd.go:69), which **is** outside the state root; the journal records only allowlisted unit *names*, not paths.

### 3.2 Correct-semantics checklist

| Required semantic | Status | Evidence |
|---|---|---|
| Dedicated fresh-install rollback/cleanup | **PARTIAL** — in-process only | `CleanupFresh` [`linux_adapter.go:538`](internal/deploy/linux_adapter.go:538); no post-crash path (RF-1) |
| Failed fresh install must not appear successful | **SATISFIED** | `fail` returns `ErrTransaction`; no commit on failure [`transaction.go:137`](internal/deploy/transaction.go:137); `ErrRecovered` on recovered failure [`transaction.go:146`](internal/deploy/transaction.go:146) |
| Partial project-owned changes recoverable | **PARTIAL** — in-process only; runtime sets lost on crash (RF-2) | [`linux_adapter.go:41`](internal/deploy/linux_adapter.go:41) |
| Unrelated host resources untouched | **MOSTLY** — ownership-bounded, but unvalidated `XrayDir`/`OriginDir` `RemoveAll` (RF-3) | [`journal.go:38`](internal/deploy/journal.go:38) vs [`linux_adapter.go:577`](internal/deploy/linux_adapter.go:577) |
| Bounded recovery | **SATISFIED** | 30 s timeout [`transaction.go:141`](internal/deploy/transaction.go:141) |
| Accurate state | **SATISFIED for manifest / PARTIAL for journal** | commit-last [`transaction.go:114`](internal/deploy/transaction.go:114); unused journal fields (RF-2) |
| Diagnosable recovery failure | **PARTIAL** — journal echoed; no machine-actionable re-run | [`main.go:336`](cmd/splitterctl/main.go:336); ack-only [`main.go:345`](cmd/splitterctl/main.go:345) |

**Confidence: HIGH.**

---

## 4) ISSUE B verdict — DesiredState completeness

**VERDICT: the audit's concerns are CONFIRMED in full. Confidence: HIGH.**

`DesiredState` ([`model.go:78`](internal/deploy/model.go:78)) is an in-memory struct (never persisted; the persisted type is `Manifest`).

| Deterministic convergence requires | `DesiredState` contains | Evidence |
|---|---|---|
| Splitter binary **hash** | `Version`, `Path` only — no `SHA256` | [`request.go:193`](internal/deploy/request.go:193) |
| Xray binary hash | `SHA256` **overloaded** with `realityFingerprint(r.Reality)` (public-param digest), not a binary hash | [`request.go:194`](internal/deploy/request.go:194), [`request.go:161`](internal/deploy/request.go:161) |
| Origin: Caddyfile hash, ACME challenge/email, CDN trust, upstream, origin port | `OriginState{Mode, Version, Domain}` only | [`model.go:41`](internal/deploy/model.go:41) |
| UnitDir, LogDir, DataDir, BinaryPrefix, unit-file paths | `Paths{StateRoot, Env, Config}` only | [`model.go:47`](internal/deploy/model.go:47) |
| Unit-file content hash | `ServiceState.Hash` left empty by `Desired()` | [`request.go:184`](internal/deploy/request.go:184), compared [`planner.go:41`](internal/deploy/planner.go:41) |
| Pairing fingerprints compared | compares **only `State`** | [`planner.go:40`](internal/deploy/planner.go:40) |
| Firewall rules reconstructible | `RulesHash` = order-insensitive sorted-concat fingerprint | [`request.go:166`](internal/deploy/request.go:166) |

### 4.1 Planner no-op analysis

[`PlanDesired()`](internal/deploy/planner.go:10) short-circuits at [`transaction.go:68`](internal/deploy/transaction.go:68) **before** writing the journal. For a genuinely identical desired state it is a **clean no-op** (pinned by [`planner_test.go:26`](internal/deploy/planner_test.go:26), [`transaction_test.go:43`](internal/deploy/transaction_test.go:43)). But:

1. **RF-4 (HIGH) — spurious drift + pairing-state loss.** [`Desired()`](internal/deploy/request.go:180) hard-codes `Pairing.State = "none"` ([`request.go:199`](internal/deploy/request.go:199)), while `pairCommand` commits the real state (`a-generated`/`a-applied`/`finalized`) ([`main.go:671`](cmd/splitterctl/main.go:671)). Re-running the *same* `install` after pairing compares `"finalized"` vs `"none"` ([`planner.go:40`](internal/deploy/planner.go:40)) → drift → full transaction re-runs → manifest rebuilt from `t.Desired` ([`transaction.go:106`](internal/deploy/transaction.go:106)) → **pairing state silently reset to `none`**. Identical-request re-apply is NOT a clean no-op once pairing has occurred.
2. **Spurious miss — unit content.** Changed unit file invisible (`Hash` empty both sides; name/component only).
3. **Spurious miss — origin/Caddyfile.** No content hash in `OriginState`.
4. **Spurious miss — splitter binary.** Same `Path`+`Version`, different bytes → invisible ([`planner.go:26`](internal/deploy/planner.go:26)).
5. **Cosmetic inconsistency (documented):** `Desired()` records `iran-origin.service` for all non-`none` modes ([`request.go:187`](internal/deploy/request.go:187)) while `BuildSystemdPlan` only renders it for caddy/cdn-tlsOrigin ([`systemd_plan.go:50`](internal/deploy/systemd_plan.go:50)).

### 4.2 Secret-persistence gaps — NONE FOUND

`Manifest` ([`model.go:14`](internal/deploy/model.go:14)), `Revision` ([`model.go:71`](internal/deploy/model.go:71)), and `ArtifactJournal` ([`journal.go:26`](internal/deploy/journal.go:26)) have **no secret-bearing field**. `Pairing.Fingerprints` holds `fingerprint(encoded blob)` (a digest), never the blob ([`pair.go:26`](internal/deploy/pair.go:26)). The secret is produced only by `InstallRequest.Env()` ([`request.go:103`](internal/deploy/request.go:103)) and excluded from `DesiredState` by construction ([`request.go:178`](internal/deploy/request.go:178)). Verified by [`controller_test.go:39`](internal/deploy/controller_test.go:39). Diagnostics force `Redacted = true` on every finding ([`diagnostics.go:53`](internal/deploy/diagnostics.go:53)); the only dynamic text is a **type name**, not an error value ([`diagnostics.go:77`](internal/deploy/diagnostics.go:77)); `recover` echoes the secret-free journal (it does echo absolute paths — minor topology disclosure). *Out-of-scope, tracked:* credential hygiene of `.roo/mcp.json` noted at [`plans/t8b-architecture-checkpoint.md:83`](plans/t8b-architecture-checkpoint.md:83).

**Confidence: HIGH.**

---

## 5) Adapter surface + delegation mapping

### 5.1 The `Adapter` interface (9 methods, [`adapter.go:9`](internal/deploy/adapter.go:9))

| # | Method | Line |
|---|---|---|
| 1 | `Prepare(context.Context, DesiredState) error` | [`adapter.go:10`](internal/deploy/adapter.go:10) |
| 2 | `Validate(context.Context, DesiredState) error` | [`adapter.go:11`](internal/deploy/adapter.go:11) |
| 3 | `Backup(context.Context, *Manifest) error` | [`adapter.go:12`](internal/deploy/adapter.go:12) |
| 4 | `Activate(context.Context, DesiredState) error` | [`adapter.go:13`](internal/deploy/adapter.go:13) |
| 5 | `Transition(context.Context, DesiredState) error` | [`adapter.go:14`](internal/deploy/adapter.go:14) |
| 6 | `Health(context.Context, DesiredState) error` | [`adapter.go:15`](internal/deploy/adapter.go:15) |
| 7 | `Restore(context.Context, Manifest) error` | [`adapter.go:20`](internal/deploy/adapter.go:20) |
| 8 | `CleanupFresh(context.Context, DesiredState) error` | [`adapter.go:23`](internal/deploy/adapter.go:23) |
| 9 | `Uninstall(context.Context, Manifest) error` | [`adapter.go:24`](internal/deploy/adapter.go:24) |

**Only concrete adapter:** `LinuxAdapter` ([`linux_adapter.go:21`](internal/deploy/linux_adapter.go:21)), constructed by `NewLinuxAdapter` ([`linux_adapter.go:48`](internal/deploy/linux_adapter.go:48)), selected in [`installCommand`](cmd/splitterctl/main.go:214), [`rollbackCommand`](cmd/splitterctl/main.go:258), [`uninstallCommand`](cmd/splitterctl/main.go:293). It branches on `a.Request.Role`; there are **no separate Iran/Germany adapters**. Other implementers are test doubles only ([`adapter_test.go:10`](internal/deploy/adapter_test.go:10), [`controller_test.go:14`](internal/deploy/controller_test.go:14)).

### 5.2 Capability → authoritative package mapping (T2–T6)

| Adapter capability | Delegates to | Reference |
|---|---|---|
| Prepare: user/group | `systemd.EnsureUser` | [`systemd/user.go:49`](internal/systemd/user.go:49) |
| Prepare: state/log/data dirs | `systemd.EnsureStateDir` / `EnsureLogDir` / `EnsureDataDir` | [`user.go:84`](internal/systemd/user.go:84), [`129`](internal/systemd/user.go:129), [`145`](internal/systemd/user.go:145) |
| Prepare: Xray binary install | `xray.Installer.Install` | [`xray/install.go:152`](internal/xray/install.go:152) |
| Prepare: origin binary install | `origin.Installer.Install` | [`origin/install.go:181`](internal/origin/install.go:181) |
| Validate: Reality params + config | `xray.ValidateRealityParams` / `RenderGermanyConfig` | [`realityconfig.go:81`](internal/xray/realityconfig.go:81), [`209`](internal/xray/realityconfig.go:209) |
| Validate: origin plan / Caddyfile | `origin.ValidatePlan` / `RenderCaddyfile` | [`origin.go:155`](internal/origin/origin.go:155), [`caddyfile.go:64`](internal/origin/caddyfile.go:64) |
| Validate: unit render | `systemd.RenderUnit` | [`render.go:174`](internal/systemd/render.go:174) |
| Validate: firewall plan | `firewall.ValidatePlan` | [`firewall.go:209`](internal/firewall/firewall.go:209) |
| Validate: splitter config | `config.Config.Validate` | [`config.go:263`](internal/config/config.go:263) |
| Activate: env file (secret) | `systemd.WriteEnvFile` | [`envfile.go:107`](internal/systemd/envfile.go:107) |
| Activate: binary pointer | `systemd.EnsureBinaryPointer` | [`pointer.go:58`](internal/systemd/pointer.go:58) |
| Activate: unit apply | `systemd.ApplyUnit` | [`apply.go:49`](internal/systemd/apply.go:49) |
| Activate: Germany Xray config | `xray.ActivateGermanyConfig` | [`activate.go:75`](internal/xray/activate.go:75) |
| Activate: Caddyfile | `origin.ActivateCaddyfile` | [`activate.go:97`](internal/origin/activate.go:97) |
| Transition: firewall apply | `firewall.Manager.Apply` | [`firewall.go:158`](internal/firewall/firewall.go:158) |
| Health: unit readiness | `systemd.WaitActive` / `HealthCheck` | [`health.go:42`](internal/systemd/health.go:42), [`79`](internal/systemd/health.go:79) |
| Health: TLS 1.3 preflight | `origin.ProbeTLS13` | [`preflight.go:80`](internal/origin/preflight.go:80) |
| Restore: unit rollback | `systemd.RollbackLast` / `RemoveUnit` / `RollbackEnvFile` | [`uninstall.go:55`](internal/systemd/uninstall.go:55), [`108`](internal/systemd/uninstall.go:108), [`envfile.go:185`](internal/systemd/envfile.go:185) |
| Restore/Cleanup: firewall removal | `firewall.Manager.Remove` | [`firewall.go:183`](internal/firewall/firewall.go:183) |
| CleanupFresh: xray/origin dirs | `xray.Installer.RemoveVersion` / `origin.Installer.RemoveVersion` | [`install.go:300`](internal/xray/install.go:300), [`install.go:538`](internal/origin/install.go:538) |
| Uninstall: host teardown | `systemd.DisableUnit`/`RemoveUnit`, `firewall.Remove`, both `RemoveVersion` | [`uninstall.go:21`](internal/systemd/uninstall.go:21) |
| Pairing boundary | `pairing.BlobA/BlobB` (wire), `deploy.Pairing` (persist) | [`pairing.go:267`](internal/pairing/pairing.go:267), [`pair.go:13`](internal/deploy/pair.go:13) |

**Adapter constraints to respect:** canonical paths enforced by `NewLinuxAdapter` ([`linux_adapter.go:55`](internal/deploy/linux_adapter.go:55)–[`63`](internal/deploy/linux_adapter.go:63)); Xray prefix `<BinaryPrefix>/xray` ([`linux_adapter.go:74`](internal/deploy/linux_adapter.go:74)); Germany `RequiresUnits` must include `xray-germany.service` ([`systemd_plan.go:47`](internal/deploy/systemd_plan.go:47)); `KeepAliveInterval` has no env var ([`config.go:154`](internal/config/config.go:154)) and is **not projected** (silently un-configurable).

### 5.3 Capabilities NOT covered by an existing package (genuinely new `internal/deploy` code)

| Gap | Why new | Reference |
|---|---|---|
| Post-crash re-entrant recovery orchestration (`Controller.Recover`) | No package provides it; must compose existing package calls | RF-1, [`controller.go:14`](internal/deploy/controller.go:14) |
| Persisted "actual created-by-this-transaction" set | Journal records intended/pre-state only | RF-2, [`journal.go:26`](internal/deploy/journal.go:26) |
| Containment validation of `XrayDir`/`OriginDir` | `validate()` omits it | RF-3, [`journal.go:38`](internal/deploy/journal.go:38) |
| Pairing state projection into `Desired` | `Desired()` hard-codes `"none"` | RF-4, [`request.go:199`](internal/deploy/request.go:199) |
| Origin artifact content hash / Caddyfile hash for drift | Not in `OriginState` | [`model.go:41`](internal/deploy/model.go:41) |
| `config set` and `upgrade` orchestration | Not present in `internal/deploy` | [`main.go:136`](cmd/splitterctl/main.go:136), [`153`](cmd/splitterctl/main.go:153) |

---

## 6) CI status + open issues snapshot

### 6.1 CI

Single workflow: [`.github/workflows/go.yml`](.github/workflows/go.yml:1) ("Go"). Triggers ([`go.yml:3`](.github/workflows/go.yml:3)): `push` to `[main, hardening/production-reliability]`, `pull_request`, `workflow_dispatch` (input `twoproc_race`, default false). One job `test` ("Linux build & test", `ubuntu-latest`, Go 1.21).

Steps: `gofmt` ([`go.yml:34`](.github/workflows/go.yml:34)); `go vet ./...` ([`:37`](.github/workflows/go.yml:37)); `go test ./...` ([`:40`](.github/workflows/go.yml:40), includes `internal/archtest` boundary gate); `go test -race ./...` ([`:43`](.github/workflows/go.yml:43)); pinned Xray gate v26.3.27 ([`:52`](.github/workflows/go.yml:52)); pinned Caddy gate v2.11.4 ([`:110`](.github/workflows/go.yml:110)); `go build ./...` ([`:175`](.github/workflows/go.yml:175)); L4 two-process gate `RUN_TWOPROC=1` (dispatch only, [`:178`](.github/workflows/go.yml:178)); linux/amd64 cross-build ([`:185`](.github/workflows/go.yml:185)).

**Latest CI run state on main: INACCESSIBLE VIA AVAILABLE TOOLING.** The available GitHub MCP surface exposes no Actions/check-runs tool. Verified what was checkable: `git rev-parse origin/main` = `67044df...`, and the commits API confirms `67044df` is the tip of `main` (authored 2026-09-12T14:38:53Z). **No CI conclusion is asserted.**

### 6.2 Open issues (via GitHub MCP — retrieved)

| # | Title | Updated |
|---|---|---|
| [#19](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/19) | L5 acceptance blocked: staging infra missing required transports (CDN/TLS up, VLESS+Reality down) + path blackholes established TCP flows | 2026-09-09 |
| [#20](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/20) | Session stranded when peer-side incarnation never existed: refused rebinds loop forever, client hang unbounded (L5 F2) | 2026-09-09 |
| [#21](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/21) | S16 discrepancy: closed-port target returns `0x00` + bounded termination, not RUNBOOK-expected `0x06` (L5 F3) | 2026-09-09 |
| [#12](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/12) | P3: CI does not run `test-install.sh`; workflow trigger list stale | 2026-09-01 |
| [#11](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/11) | P2: No TCP keepalive on relay sockets | 2026-09-01 |
| [#10](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/10) | P2: Review carrier liveness tuning | 2026-09-01 |
| [#9](https://github.com/Zaltapar/iran-germany-split-tunnel/issues/9) | P1: No real two-server integration test | 2026-09-01 |

No T8-specific issue exists. **#19/#20/#21 remain OPEN and must remain visible** (L5 transport/staging; stranded session/split-brain; SOCKS closed-port semantics). Do not silently close them.

### 6.3 Docs cross-check

- **Divergence #1:** [`IMPLEMENTATION_STATUS.md:4`](IMPLEMENTATION_STATUS.md:4) records latest commit `ac573c6`; HEAD is `67044df` (docs lag one commit).
- **T8 progress claims match code** ([`IMPLEMENTATION_STATUS.md:8`](IMPLEMENTATION_STATUS.md:8)–[`54`](IMPLEMENTATION_STATUS.md:54)); fresh-install semantics statement at [`:97`](IMPLEMENTATION_STATUS.md:97)–[`:102`](IMPLEMENTATION_STATUS.md:102) matches code. Doc is honest that T8 is not complete without a clean-Ubuntu L5 run ([`:27`](IMPLEMENTATION_STATUS.md:27)).
- **Divergence #2:** [`README.md`](README.md:1) contains **zero** references to `splitterctl` / `T8` / `recover` / `journal`; the entire T8 CLI surface is undocumented for users.
- T2–T6 review docs present: [`docs/reviews/t2-xray-installer-review.md`](docs/reviews/t2-xray-installer-review.md:1), [`t3-reality-config-review.md`](docs/reviews/t3-reality-config-review.md:1), [`t4-origin-review.md`](docs/reviews/t4-origin-review.md:1), [`plans/t3-design.md`](plans/t3-design.md:1), [`plans/t5-design.md`](plans/t5-design.md:1), [`plans/t8-design.md`](plans/t8-design.md:1), [`docs/self-contained-deployment-architecture.md`](docs/self-contained-deployment-architecture.md:30).

---

## 7) Recommended milestone ordering for remaining T8-B work

Ordering principle: fix correctness/safety of *recovery* and *idempotency* before adding new commands or L5 acceptance, so that any later failure is recoverable and re-runnable. Smallest safe first step first.

1. **M1 — Containment hardening of journal-driven deletion (RF-3).** Smallest, highest-severity, lowest-risk change: validate `XrayDir`/`OriginDir` against `BinaryPrefix` in `ArtifactJournal.validate()` ([`journal.go:38`](internal/deploy/journal.go:38)) and make `CleanupFresh` removal prefix-bounded and symlink-safe ([`linux_adapter.go:577`](internal/deploy/linux_adapter.go:577)). Pure hardening; no behaviour change for valid state.
2. **M2 — Make identical re-apply a true no-op (RF-4).** Project committed pairing state into `Desired()` ([`request.go:199`](internal/deploy/request.go:199)) so re-running `install` after pairing does not reset pairing state. Add a regression test.
3. **M3 — Post-crash re-entrant recovery (RF-1 + RF-2).** Persist the actual created-by-this-transaction set, add `Controller.Recover()` composing the existing adapter recovery, and make `splitterctl recover` (without `--ack`) drive it; keep `--ack` as explicit force-clear. This removes the operator deadlock.
4. **M4 — DesiredState convergence completeness (ISSUE B).** Add splitter/origin/unit content hashes and the missing managed paths; make planner comparisons content-aware.
5. **M5 — `config set` and `upgrade` orchestration.**
6. **M6 — Documentation + L5 acceptance.** Update `README.md` and `IMPLEMENTATION_STATUS.md`; run clean-Ubuntu L5 acceptance (depends on #19 staging infra).

**Smallest safe first implementation step:** **M1 (RF-3 containment hardening)** — a bounded, self-contained validation + prefix-safe deletion change with a direct regression test, requiring no protocol or lifecycle redesign.

---

## Appendix — Red-flag register

| ID | Red flag | Severity | Evidence | Remediation | Confidence |
|---|---|---|---|---|---|
| RF-1 | No post-crash recovery entrypoint; operator deadlocked (install/rollback/uninstall all refuse on stale journal) | HIGH | [`controller.go:46`](internal/deploy/controller.go:46), [`79`](internal/deploy/controller.go:79), [`100`](internal/deploy/controller.go:100); [`main.go:345`](cmd/splitterctl/main.go:345) | Add `Controller.Recover()`; wire `recover` to execute it | HIGH |
| RF-2 | Recovery depends on runtime-only in-memory sets; journal `Files`/`Units`/`PreUnits` never read | HIGH | [`linux_adapter.go:41`](internal/deploy/linux_adapter.go:41), [`544`](internal/deploy/linux_adapter.go:544), [`560`](internal/deploy/linux_adapter.go:560); [`journal.go:26`](internal/deploy/journal.go:26) | Persist actual created-set; consume in recovery | HIGH |
| RF-3 | `os.RemoveAll` on unvalidated `j.XrayDir`/`j.OriginDir` | HIGH | [`linux_adapter.go:577`](internal/deploy/linux_adapter.go:577), [`583`](internal/deploy/linux_adapter.go:583); [`journal.go:38`](internal/deploy/journal.go:38) | Validate against `BinaryPrefix`; prefix-bounded, symlink-safe removal | HIGH |
| RF-4 | Re-running `install` after pairing detects spurious drift and resets pairing state to `none` | HIGH | [`request.go:199`](internal/deploy/request.go:199), [`planner.go:40`](internal/deploy/planner.go:40), [`transaction.go:106`](internal/deploy/transaction.go:106), [`main.go:671`](cmd/splitterctl/main.go:671) | Project committed pairing state into `Desired()` | HIGH |
