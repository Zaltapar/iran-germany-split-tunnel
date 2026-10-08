# One-Click Installer — Iran/Germany Split-Tunnel

`install-oneclick.sh` is the **outer bootstrap only**. It prepares a clean
Ubuntu/Debian host (packages, Go toolchain, source acquisition, builds) and
then **delegates every host mutation to `splitterctl`** — the transactional
deployment CLI that owns state, journaling, doctor, and rollback
(`splitterctl recover`). The installer never re-implements state or rollback.

Design: [`plans/oneclick-installer-design.md`](../plans/oneclick-installer-design.md).

> **Status:** implemented and exercised locally (`bash -n`,
> `--dry-run` for both roles, and the `install-oneclick.test.sh` harness,
> which now also covers the `certbot-arvan` dashboard TLS path). The
> certbot DNS-01 flow was additionally validated against a live ArvanCloud
> API on the Germany host (create/read/delete of a TXT record, plus
> propagation checks) during host acceptance testing.

---

## Safety Model

| Property | How it is enforced |
|----------|-------------------|
| Strict shell | `set -euo pipefail`, `IFS=$'\n\t'`, strict quoting; no `eval`, no `curl \| bash`; every remote byte is SHA-256-verified before use. |
| Root + distro gate | Refuses to proceed without root, and on non-Ubuntu/Debian distros (dry-run degrades to a notice so the plan can be printed on a dev box). |
| No routing/DNS/egress | The installer never touches routing tables, DNS, or egress. |
| Firewall is opt-in | `--open-firewall` adds *only* the role's specific ports via `splitterctl install` (`SPLITTERCTL_FW_ALLOW`). Without the flag, no firewall mutation happens. |
| One secret carried | The only human-carried secret is **Blob A** (Iran → Germany). **Blob B is public** (Reality public params + down host/port) and is never carried on the secret path; only fingerprints of blobs are logged. `--pairing-secret-file` is securely deleted after use. |
| No secrets in logs | The install log (`/var/log/split-tunnel-install.log`, 0600) and stdout carry fingerprints and *names* of secrets only — never values. The dashboard basePath and admin token are generated credentials (not the tunnel secret); they are written to their on-disk homes (the 0640 dashboard `config.json` and the 0600 token file) and are **never echoed to stdout or the log** — recover them from those files. |
| Rollback | Always `splitterctl recover` (journal-driven) — the installer adds no alternative path. |

---

## One-Command Usage

### Prerequisites (per host)

- A fresh **Ubuntu 22.04/24.04** (or Debian 12+) VPS, reachable as root.
- The uploaded domain `--domain` pointing (CDN/origin) at the host.
- Dashboard (Germany only): a TLS cert+key PEM pair for the domain
  (`--cert`, `--key`).
- Enough disk under `/opt` (checked; degraded in dry-run).

### Iran host

```bash
# 1. Bootstrap + install (prints the plan first if you add --dry-run):
./install-oneclick.sh --role iran --domain ctoplace.ir --source . --no-clone

# 2. Pairing handoff (single secret): the installer runs `splitterctl pair
#    generate` and writes Blob A to /root/.pairing/blob-a (0600).
#    THE OPERATOR copies exactly this one file to the Germany host and
#    deletes it locally. Nothing else is carried.

# 3. On Iran, after Germany has returned Blob B (see below), finalize:
./install-oneclick.sh --role iran --domain ctoplace.ir --source . --no-clone \
    --pairing-secret-file /root/.pairing/blob-b
```

With `--iran-xray managed` (default) the finalize step provisions the
**project-managed Xray consumer** (`install-extra xray-consumer`): pinned
Xray-core + binary pointer, `xray-consumer.json` rendered deterministically
from Blob B's public params, and the `xray-consumer.service` unit applied
transactionally. With `--iran-xray external` the installer instead prints a
3x-ui paste-in snippet for your own Xray instance.

### Germany host

```bash
./install-oneclick.sh --role germany --domain ctoplace.ir --source . --no-clone \
    --dashboard on --dashboard-port 8443 \
    --cert /root/dashboard.crt --key /root/dashboard.key \
    --pairing-secret-file /root/.pairing/blob-a
```

This performs the full Germany install, applies the carried **Blob A**
(the only secret the operator carried), and — because it is *public*
material — deterministically emits the return **Blob B** to
`/root/.pairing/blob-b`, which the operator carries back to Iran for step 3.
Blob B is then securely deleted on both sides.

### Dashboard access (Germany)

- URL: `https://<germany-host>:8443/<basePath>/` — the random 32-hex
  `basePath` is the first access secret (generated at install; read it from
  `/etc/split-tunnel/dashboard/config.json`, it is never printed).
- The dashboard binds `0.0.0.0` **only** when TLS is complete (cert + key +
  32-hex basePath); otherwise the strict loopback bind applies.
- Security headers (HSTS, CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`) are set on every TLS response.
- An admin Bearer token is generated at
  `/etc/split-tunnel/dashboard/token` (0600, value read from that file, never
  printed); it gates the (currently disabled) mutation endpoints.
  **Mutations stay 403.**
- Certs/key live under `/etc/split-tunnel/dashboard/tls/`
  (0640 `root:split-tunnel`).
- **The dashboard is hosted on Germany only. It never binds a public port on
  Iran.** The Iran node is collected read-only via the pinned-SSH collector
  (pinned host keys, fixed argv allowlist; see
  [tunneldash.md](tunneldash.md)).

---

## Dashboard TLS via certbot DNS-01 (Arvan)

By default the installer uses an **existing** cert/key pair passed with
`--cert` / `--key`. On hosts where the dashboard is reached directly by FQDN
(the record is DNS-only, not CDN-proxied, and port 443 is already owned by
xray) the installer can instead **obtain the TLS cert itself** via Let's
Encrypt DNS-01 through the ArvanCloud API. This avoids needing an HTTP-01
endpoint on :80 and an ACME HTTPS endpoint on :443.

### Prerequisites

- An ArvanCloud-managed zone for the dashboard domain (e.g. `ctoplace.ir`).
- An ArvanCloud API token (a CDN API key, not a user password). Put it in a
  0600 env file on the dashboard host:

  ```bash
  # On the Germany host:
  install -d -m 0700 /etc/split-tunnel/arvan
  # Then, from a trusted operator machine (NEVER paste it into a commit or
  # the command line visible in process lists):
  scp your-local-arvan.env root@91.107.152.1:/etc/split-tunnel/arvan/env
  ssh root@91.107.152.1 'chmod 0600 /etc/split-tunnel/arvan/env'
  ```

  The local env file must contain exactly one line:
  `ARVAN_API_KEY=<your token>`. It is read on the host, sourced, and the key
  is passed to `curl` via a 0600 config file — it is never printed to logs,
  stdout, or argv.

- A DNS-only A record pointing the dashboard FQDN at the Germany host IP
  (so the dashboard is reached directly, not through the CDN edge). Only that
  one new record is created; no other DNS records are touched.

### Usage

```bash
./install-oneclick.sh --role germany --domain ctoplace.ir \
    --source . --no-clone \
    --dashboard on --dashboard-port 8443 \
    --dashboard-domain dash.ctoplace.ir \
    --dashboard-cert-mode certbot-arvan \
    --arvan-api-key-file /etc/split-tunnel/arvan/env
```

What happens on the host (fail-closed; any error aborts the install):

1. `certbot` is installed via `apt` if missing.
2. The Arvan DNS-01 hook
   [`scripts/certbot-arvan-dns.sh`](../scripts/certbot-arvan-dns.sh) is
   installed to `/opt/split-tunnel/scripts/certbot-arvan-dns.sh` (0755).
   It reads the API key from the 0600 env file and manages the
   `_acme-challenge.<leaf>` TXT record on the Arvan zone, waiting for public
   DNS propagation.
3. `certbot certificate issue --manual --preferred-challenges dns` runs with
   the hook as the manual auth + cleanup hook. No port 80 or 443 is used.
4. The issued PEMs are copied to `/etc/split-tunnel/dashboard/tls/{cert,key}.pem`
   (0640 `root:split-tunnel`).
5. A certbot **deploy hook** is written to
   `/etc/letsencrypt/renewal-hooks/deploy/split-tunnel-dashboard.sh` that
   re-copies the live PEMs and `systemctl restart tunneldash.service` on
   every renewal. `certbot renew` (enabled by `certificate issue`) runs via
   the systemd `certbot.timer`.

### Renewal

Automatic — `certbot.timer` (installed by the `certbot` package) triggers
`certbot renew` daily; each renewal re-runs the DNS-01 auth/cleanup hooks
and the deploy hook, which restarts `tunneldash`.

To check the next renewal date and remaining days:

```bash
sudo certbot certificates
sudo systemctl list-timers | grep certbot
```

Forced renewal (for testing):

```bash
sudo certbot renew --force-renewal -d dash.ctoplace.ir
```

### Rollback

The `certbot-arvan` flow writes PEMs into the **same** on-disk location as
the `--cert/--key` path, so rolling back is trivial:

```bash
# 1. Stop the dashboard so the TLS dir is not in use:
sudo systemctl stop tunneldash.service

# 2. Replace the PEMs with the previous cert/key pair:
sudo cp /root/dashboard.crt /etc/split-tunnel/dashboard/tls/cert.pem
sudo cp /root/dashboard.key /etc/split-tunnel/dashboard/tls/key.pem
sudo chown root:split-tunnel /etc/split-tunnel/dashboard/tls/{cert,key}.pem
sudo chmod 0640 /etc/split-tunnel/dashboard/tls/{cert,key}.pem

# 3. Restart:
sudo systemctl start tunneldash.service
```

To fully delete the certbot-managed cert and its renewal entry:

```bash
sudo certbot delete -d dash.ctoplace.ir
```

---

## Flags and Environment Equivalents

| Flag | Env equivalent | Notes |
|------|----------------|-------|
| `--role iran\|germany` | `ONECLICK_ROLE` | required |
| `--source <url\|path>` | `ONECLICK_SOURCE` | git URL, tarball URL, or local path |
| `--ref <gitref>` | `ONECLICK_REF` | default `main` |
| `--no-clone` | `ONECLICK_NO_CLONE=1` | use a local source path |
| `--dashboard on\|off` | `ONECLICK_DASHBOARD` | Germany only (default off) |
| `--iran-xray managed\|external` | `ONECLICK_IRAN_XRAY` | default managed |
| `--domain <upload-domain>` | `ONECLICK_DOMAIN` | public upload domain |
| `--dashboard-port <port>` | `ONECLICK_DASHBOARD_PORT` | default 8443 |
| `--cert <pem> --key <pem>` | — | existing Arvan/CDN cert+key for dashboard TLS |
| `--dashboard-domain <fqdn>` | `ONECLICK_DASHBOARD_DOMAIN` | dashboard public FQDN (Germany); implies certbot-arvan when no cert mode given |
| `--dashboard-cert-mode <existing\|certbot-arvan>` | `ONECLICK_DASHBOARD_CERT_MODE` | `existing` = use `--cert/--key`; `certbot-arvan` = obtain via certbot DNS-01 + Arvan API |
| `--arvan-api-key-file <path>` | `ONECLICK_ARVAN_API_KEY_FILE` | 0600 file with `ARVAN_API_KEY=<token>` (certbot-arvan mode) |
| `--pairing-secret-file <path>` | `ONECLICK_PAIRING_SECRET_FILE` | operator-carried blob (0600); securely deleted after use |
| `--open-firewall` | `ONECLICK_OPEN_FIREWALL=1` | opt-in: role-specific firewall ports only |
| `--dry-run` | `ONECLICK_DRY_RUN=1` | print the exact commands, change nothing |
| `--uninstall` | `ONECLICK_UNINSTALL=1` | delegate to `splitterctl uninstall` |
| `--yes` | `ONECLICK_YES=1` | non-interactive |
| `--help` | — | usage + exit 0 |

## The Single Manual Pairing Step

1. **Iran** — bootstrap runs `splitterctl pair generate`: Blob A
   (tunnel secret + public upload domain) is written to
   `/root/.pairing/blob-a` (0600). **This is the only secret the operator
   ever carries.**
2. **Operator** — copies that one file to the Germany host.
3. **Germany** — bootstrap runs `splitterctl pair apply` with the carried
   Blob A; it deterministically emits the **public** Blob B (Reality public
   key/SNI/shortId/UUID + down host/port) to `/root/.pairing/blob-b` and
   logs fingerprints only.
4. **Operator** — carries Blob B back to Iran (it is public; no secret
   handling required).
5. **Iran** — `splitterctl pair finalize` consumes Blob B; the carried
   secret file is securely deleted. The managed xray-consumer is
   (re)provisioned from Blob B's public params in the same step.

## Uninstall

```bash
./install-oneclick.sh --role iran  --uninstall        # delegates to `splitterctl uninstall`
./install-oneclick.sh --role germany --uninstall
./install-oneclick.sh --role iran  --uninstall --yes  # non-interactive (--purge)
```

`xray-consumer.service` and `tunneldash.service` are part of the protected
unit set, so uninstall handles them transactionally like the core units.

## Dry-Run (Local, No Host Changes)

```bash
./install-oneclick.sh --role iran    --domain ctoplace.ir --source . --no-clone --dry-run
./install-oneclick.sh --role germany --domain ctoplace.ir --source . --no-clone \
    --dashboard on --dry-run
```

Both print the full command plan and **exit 0** without creating any host
paths. This is how the installer is exercised on a dev box.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `abort: not root` | Run as root (the installer refuses non-root in live mode). |
| `abort: unsupported OS` | Distro must be Ubuntu/Debian. Dry-run downgrades this to a notice. |
| `abort: not enough free space under /opt` | The disk check is pipefail-safe and skips when `df` is unavailable; free space under `/opt` in live mode. |
| Toolchain install fails | The installer prefers the distro's Go; otherwise it fetches a pinned, SHA-256-verified tarball. Check egress to go.dev. |
| Pairing step fails | Confirm `--pairing-secret-file` holds the right blob for the right action (apply takes Blob A, finalize takes Blob B). |
| Dashboard unreachable | Verify the basePath (32-hex; read it from the dashboard `config.json`), that `--cert`/`--key` were supplied, and that the port is reachable. The unit logs go to the journal (`systemctl -o status -n 50 tunneldash`). |
| Interrupted transaction | Run `splitterctl recover` — journal-driven, bounded to the journal's pre-state. |

## Security Notes / Rotation

- **BasePath + admin token rotation:** regenerate with
  `openssl rand -hex 16` (path) / `openssl rand -hex 32` (token), update
  `/etc/split-tunnel/dashboard/config.json` (basePath) and the token file,
  then `systemctl reload tunneldash`. Both values are 0600 and owner-restricted.
- **TLS cert rotation:** replace the files under
  `/etc/split-tunnel/dashboard/tls/` and `systemctl reload tunneldash`.
- The tunnel secret (inside Blob A) is rotated through
  `splitterctl config set SPLIT_SECRET=...` — never via the dashboard, which
  rejects mutation.

---

## Explicit Statement

The installer script itself is exercised locally (`bash -n`, `--dry-run` for
both roles, and the `install-oneclick.test.sh` harness) without touching a
host. The certbot-arvan flow is additionally covered by the same dry-run
harness (side-effect free) and the hook's `bash -n` syntax check.

Host operations are performed only when the operator explicitly runs the
installer in live mode (no `--dry-run`). In that mode the installer will:

- contact the Arvan CDN API (only when `--dashboard-cert-mode certbot-arvan`
  is requested, and only to create/delete the single `_acme-challenge` TXT
  record for the given dashboard domain);
- install `certbot` and the Arvan DNS-01 hook on the dashboard host;
- obtain or renew a Let's Encrypt TLS certificate via DNS-01;
- start/restart the `tunneldash.service` unit.

All other DNS records are untouched. No secrets (Arvan API key, tunnel
secret, basePath, admin token) are ever printed to stdout, the install log,
or argv.
