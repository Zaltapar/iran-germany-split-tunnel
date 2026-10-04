# SSH Key Rotation Runbook

Status: **REFERENCE — Subtask 9 (key hygiene).** This document records the
current SSH key inventory, why it must be rotated, and the exact order of
operations to replace the keys without losing production access. It is
deliberately a runbook (procedural, copy-pasteable commands) and is **not** a
design document.

> **Do NOT rotate in this subtask.** Rotating a key invalidates the live
> production SSH path the moment the old authorized-key entry is removed.
> Rotation is the operator's deliberate action, performed outside any task
> that must keep the tunnel up. Everything here is pre-planned so the
> operator can execute it safely when ready.

## 1. Inventory — which keys exist and what they grant

All key material lives under `ssh/` (now gitignored — see §4). The **private**
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
  filesystem ACLs inherited broad access from the repo root. (Subtask 9 has
  since gitignored `ssh/` and pinned the key ACLs to
  `{current user, SYSTEM, Administrators}` — see §4 — but that is
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

## 4. Subtask 9 containment already in place

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
