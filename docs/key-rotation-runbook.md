# Key Rotation Runbook (SSH + Xray Reality)
 
Status: **REFERENCE — Subtask 9 (SSH key hygiene) + Phase C5 (Reality key
rotation via the C2/C3 control plane).** This document records:

- §1–§3 + §5: the operator **SSH** key inventory, why it must be rotated,
  and the add-before-remove order of operations (Subtask 9).
- §4: the **Xray Reality keypair** rotation, orchestrated through the C2
  control plane (kill switch, revision store, LKG, hash-chained audit log) —
  including the C5 key-file group isolation (`split-tunnel-xray`) and the
  existing-host migration step.

It is deliberately a runbook (procedural, copy-pasteable commands) and is
**not** a design document.

> **Do NOT rotate in this subtask.** Rotating a key invalidates the live
> production SSH path the moment the old authorized-key entry is removed.
> Rotation is the operator's deliberate action, performed outside any task
> that must keep the tunnel up. Everything here is pre-planned so the
> operator can execute it safely when ready.

## 1. Inventory — which keys exist and what they grant

All key material lives under `ssh/` (now gitignored — see §5). The **private**
keys are unencrypted (no passphrase), so possession of the file = full
credential value.

| File | Type | Fingerprint (SHA256) | Grants access to |
|------|------|----------------------|------------------|
| `ssh/hetzner_key` | ed25519 (OpenSSH) | `SHA256:IUmPWvnw6uNCKDVMG8dTvLDndqBLhg2HJU40Dot7KGc` (`zoocode-local`) | **Germany host** `root@91.107.152.1` (`/root/.ssh/authorized_keys`) |
| `ssh/ar-zoocode-privatekey.pem` | RSA 2048 | `SHA256:o+sU7VumMHLjvXTuPrJdPj3SJnHwNSc9CUxRnVREffw` | **Arvan / zoocode infra** (host `arvan-key.pub` is the matching public key, `SHA256:o+sU7VumMHLjvXTuPrJdPj3SJnHwNSc9CUxRnVREffw`) |
| `ssh/hetzner_key.pub` | public (ed25519) | — | Public half of the Germany key — safe, but ignored with the whole dir |
| `ssh/arvan-key.pub` | public (RSA) | — | Public half of the Arvan key — safe, but ignored with the whole dir |

Notes:
- The two `.pub` files contain **no** secret material; they are only ignored
  because the whole `ssh/` directory is gitignored.
- `ssh/hetzner_key` is the key the local tooling (and this subtask) uses to
  reach the Germany host: `ssh -i ssh/hetzner_key root@91.107.152.1`.

## 2. Why rotate

- Both private keys are **unencrypted** (no passphrase). A leaked file is an
  immediate credential compromise.
- Until subtask 9 the `ssh/` directory was **not** gitignored and the
  the filesystem ACLs inherited broad access from the repo root. (Subtask 9 has
  since gitignored `ssh/` and pinned the key ACLs to
  `{current user, SYSTEM, Administrators}` — see §5 — but that is
  containment, **not** a cure. Once a key's bytes have sat in a directory
  with wide ACLs / were at risk of being committed, treat it as possibly
  exposed and rotate.)
- Rotation is the only way to guarantee the compromised bytes no longer
  grant access.

## 3. Order of operations — no lockout

The golden rule: **never remove the old authorized key until the new one is
proven to work.** For each host, add-before-remove.

### 3.1 Germany host (`root@91.107.152.1`)

Generate a **new, passphrase-protected** key locally (keep it out of `ssh/`
until verified; never commit it — it will be gitignored regardless):

```bash
# Windows (Git Bash / OpenSSH) — generate a new ed25519 key WITH a passphrase
ssh-keygen -t ed25519 -C "zoocode-germany-<date>" -f ./.ssh/hetzner_key.new
#  ...enter and confirm a strong passphrase...
```

Install the **new** public key alongside the old one (append; do NOT remove
the old line yet):

```bash
ssh -i ssh/hetzner_key root@91.107.152.1 \
  "cat >> /root/.ssh/authorized_keys" <<< "$(.ssh/hetzner_key.new.pub)"
```

Prove the new key works **before** touching the old one:

```bash
ssh -i .ssh/hetzner_key.new root@91.107.152.1 "echo OK-from-new-key"
```

Only after that line prints `OK-from-new-key`:

```bash
ssh -i ssh/hetzner_key root@91.107.152.1 \
  "sed -i '\#IUmPWvnw6uNCKDVMG8dTvLDndqBLhg2HJU40Dot7KGc#d' /root/.ssh/authorized_keys"
```

(Remove the old public key line by its `zoocode-local` fingerprint
`SHA256:IUmPWvn...` — identify it with `ssh-keygen -lf /root/.ssh/authorized_keys`
if needed.) Then update local tooling/config to use `.ssh/hetzner_key.new`
and delete `ssh/hetzner_key`.

### 3.2 Arvan / zoocode host

Same add-before-remove pattern with a fresh RSA or (preferably) ed25519 key:

```bash
ssh-keygen -t ed25519 -C "zoocode-arvan-<date>" -f ./.ssh/arvan-key.new
# Install new pub to the Arvan host's /root/.ssh/authorized_keys (append),
# verify with:  ssh -i .ssh/arvan-key.new <arvan-host> "echo OK"
# Only then remove the old line whose fingerprint is
# SHA256:o+sU7VumMHLjvXTuPrJdPj3SJnHwNSc9CUxRnVREffw,
# then delete ssh/ar-zoocode-privatekey.pem.
```

### 3.3 Lockout guard-rails

- **Never** run the `sed`/removal while the only open session is the one that
  would die — keep at least one live session on the *old* key open until the
  *new* key is confirmed working from a separate client.
- Always add new pub → verify new key → remove old pub, in that order, per host.
- Keep the old private key on disk for 24–48 h after removal, in case you
  need to roll back; shred it only then.

## 4. Reality key (Xray) rotation — C2/C3 control plane

The Xray **Reality keypair** (the `privateKey` inside
`/etc/split-tunnel/xray-germany.json`) is a *different* class of key from the
SSH keys above. Since C5 it is group-isolated: the file converges to
`0640 root:split-tunnel-xray` and **only the `xray-germany.service` unit
belongs to that group** (via `SupplementaryGroups=split-tunnel-xray`). The
`tunneldash.service` process (user `split-tunnel`, group `split-tunnel`) is
**deliberately excluded** from the key group, so the dashboard cannot read
the private key. Rotating the Reality key is therefore a host-side,
root-privileged control-plane operation — never a dashboard mutation.

> **C5 note (existing hosts):** installs that predate C5 have
> `xray-germany.json` at `0640 root:split-tunnel` (or `0600 root:root`), and
> the `split-tunnel-xray` group may not exist yet. Run §4.1 first to
> provision the group and converge the file; subsequent rotations then use
> the standard path.

### 4.1 Existing-host migration (first time only)

```bash
# On the Germany host, as root. Provisions the key group, converges the
# state dir, and re-renders the xray unit so it joins the key group.
splitterctl install-extra tunneldash    # (re)applies the extra units incl. xray
# or, if you only need the group + perms without touching services:
groupadd --system split-tunnel-xray 2>/dev/null || true
chown root:split-tunnel-xray /etc/split-tunnel/xray-germany.json
chmod 0640 /etc/split-tunnel/xray-germany.json
systemctl edit xray-germany.service   # add SupplementaryGroups=split-tunnel-xray
                                      # then `systemctl daemon-reload`
# verify the service user is DENIED the key (must print 'denied'):
runuser -u split-tunnel -- sh -c 'test -r /etc/split-tunnel/xray-germany.json && echo readable || echo denied'
```

Do NOT restart `xray-germany.service` as part of a pure permission
convergence — the running process keeps its open fd; the new group only
affects future starts and the rotation flow below.

### 4.2 Pre-rotation checks

```bash
# 1. Confirm the control agent is healthy and the audit chain is intact.
systemctl is-active split-tunnel-ctl.service
splitterctl control audit-verify
# Expect: "audit-verify: chain intact (N entries)"

# 2. Confirm the kill switch is NOT engaged (you cannot rotate while frozen
#    unless you deliberately intend to; freeze blocks all mutating ops).
ls -l /var/lib/split-tunnel-ctl/killswitch 2>/dev/null && echo FROZEN || echo NOT-FROZEN

# 3. Snapshot the current key fingerprint (public half only, no secret).
xray --version   # pinned binary
# The stored revision's pre/ copy retains the old key; this is the
# LKG (last-known-good) the rollback below restores.
```

### 4.3 Rotate — freeze → rotate → verify → unfreeze

The rotation is orchestrated through the C2 control plane so every step is
audit-logged and the old key is retained in the revision store.

```bash
# 1. Freeze: engage the kill switch so no concurrent mutation can race the
#    rotation. All mutating dashboard/agent ops now return `frozen`.
splitterctl control freeze
# Expect: "control: kill switch engaged at /var/lib/split-tunnel-ctl/killswitch;
#          all mutating ops now return frozen"

# 2. Rotate the Reality keypair for instance `a`. The new key is generated
#    server-side by the pinned xray binary; the OLD key is retained in the
#    revision store's pre/ copy automatically. --retain-old=false is refused
#    by the CLI by design (the transition window needs both).
splitterctl control rotate-key a
# Expect: "control rotate-key: instance a rotated (new-key fingerprint
#          <12-hex>); the old key is retained in the revision store for the
#          transition window"
# NOTE: the CLI prints ONLY a 12-hex sha256 fingerprint of the new key.
#       The new private key is written 0600 into the revision store and
#       rendered into /etc/split-tunnel/xray-germany.json at 0640
#       root:split-tunnel-xray. No secret is ever placed on argv or stdout.

# 3. The rotation rewrites the live config atomically (tmp+fsync+rename) and
#    restarts xray-germany.service + settles. Confirm it came back:
systemctl is-active xray-germany.service
# Expect: active

# 4. Verify the new key is actually serving (Reality handshake from an Iran
#    client or the xray -test gate already ran during apply). A clean,
#    authenticated tunnel end-to-end is the verification of success.

# 5. Unfreeze: clear the kill switch so normal operation resumes.
splitterctl control unfreeze
# Expect: "control: kill switch cleared; applying is permitted again"
```

### 4.4 Peer coupling (Iran side)

The Iran consumer config (`/etc/xray-consumer/config.json`) carries only the
**public** Reality params (public key, SNI, shortID, UUID, port). When the
Germany key rotates, the public half changes and the Iran consumer MUST be
re-pointed to the new public params or it will stop handshaking.

```bash
# On Germany: stage the public Blob B for the Iran host (0600 file, content
# never printed; only its fingerprint is shown).
splitterctl control export-blob b /root/blob-b.new
# Expect: "control export-blob: staged blob b at /root/blob-b.new (fingerprint <12-hex>)"

# Carry blob-b.new to the Iran host (sftp, not email), then:
# On Iran: import + apply via the C4 agent (the C3 staging validates and
# records; the C4 agent performs the swap + restart of xray-consumer).
splitterctl control import-blob b /root/blob-b.new
# Expect: "control import-blob: staged blob b (revision r-c3-import-b);
#          apply it on this host with the C4 agent"
```

### 4.5 Rollback drill (revert to last-known-good)

If the new key misbehaves (tunnel down, clients fail to handshake, xray
crash-loops), revert the rotation to the retained old key:

```bash
# revert-lkg is callable EVEN WHEN FROZEN — it is the one mutating op the
# kill switch permits, because it is the escape hatch.
splitterctl control revert-lkg
# Expect: "control: revert-lkg <restored|nothing-to-revert> (revision <id>)"

# The reverted xray config is the pre-rotation revision (old key). Confirm:
systemctl is-active xray-germany.service
# Then verify the tunnel end-to-end again before unfreezing.
splitterctl control unfreeze
```

**Drill (do this on a scratch clone, not production):** after every
successful rotation, run `revert-lkg` in a maintenance window to confirm
the LKG copy actually restores a working key, then rotate forward again.
This proves the rollback path before you need it.

### 4.6 Reading the audit trail after a rotation

```bash
# Re-hash the whole agent audit chain (tamper-evident; every entry is
# redacted — key material is stored only as fingerprints).
splitterctl control audit-verify
# On a tamper or a gap the chain verify FAILS with the first broken entry.
# Tail the redacted log to confirm the rotate + revert events are recorded:
tail -n 40 /var/lib/split-tunnel-ctl/audit.jsonl | grep -E 'rotate|revert|freeze|swap'
# (The audit log never contains the key bytes — grep is safe to run/read.)
```

### 4.7 Failure table

| Symptom | Likely cause | Action |
|---|---|---|
| `rotate-key` refused: `frozen` | kill switch engaged | `control unfreeze` (or finish the in-flight op), then retry |
| `--retain-old=false` blocked | operator passed the flag | remove the flag; retention is mandatory for the transition |
| `xray -test` gate fails during apply | rendered config invalid | no swap occurs (atomic); fix params, re-run `rotate-key` |
| `xray-germany` crash-loops post-rotation | new key incompatible with Iran | `control revert-lkg`, re-verify, then rotate forward + re-export Blob B |
| `audit-verify` FAILED | chain tampered / gap | `control recover` (design §5.6 crash-recovery table); do NOT trust the LKG until the chain verifies |
| `runuser -u split-tunnel test -r` says the key is `readable` | C5 group isolation not applied | re-run §4.1; confirm `SupplementaryGroups=split-tunnel-xray` is on the xray unit only |

## 5. Subtask 9 containment already in place

These are **not** the rotation itself — they are the hygiene that reduces
blast radius *before* rotation:

- `.gitignore` now excludes `ssh/` and backstops on `*.pem`, `*.key`,
  `id_rsa*`, `id_ed25519*`. Git history was verified read-only to contain
  **no** key blobs (no rewrite was required or performed).
- The two private-key files had their ACLs pinned (inheritance removed) to
  exactly `{current user, NT AUTHORITY\SYSTEM, BUILTIN\Administrators}` via
  `icacls ... /inheritance:r /grant:r ...`. No other local principal retains
  access, and SSH tooling was confirmed still able to read both keys after
  the change.

**Next deliberate action for the operator:** perform §3 (Germany first, then
Arvan), with a passphrase on every new key.
