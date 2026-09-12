# SSH demo

A stock OpenSSH server that authenticates entirely through xdauth: no password, no public key, `PasswordAuthentication no` the whole time.

## Run it

```sh
docker compose -f deploy/compose/compose.yaml up --build
```

This starts three containers: `dex` (a mock OIDC provider with one static user, `testuser` / `password`), `broker` (`xdauth-broker`), and `sshd` (stock OpenSSH + PAM + `xdauth-pam`).

**Requires a Linux Docker host** (a real Linux machine, a Linux VM, or a Linux CI runner — not Docker Desktop's macOS/Windows VM): `dex` and `broker` run with `network_mode: host` so dex's one issuer URL is reachable identically by the broker and by your browser, which container bridge networking alone can't guarantee. `sshd` stays on the regular bridge network and reaches the broker via `host.docker.internal` (added via `extra_hosts: host-gateway`).

## Try it

```sh
ssh -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no -p 2222 testuser@localhost
```

You'll see:

```
xdauth: to finish signing in, visit:

  http://localhost:8080/auth/verify/<id>

and enter the code: XXXX-XXXX

xdauth: waiting for approval...
```

Open that URL in a browser, log in to dex as `testuser` / `password`, check the requester context on the approval page, type the code, click Approve. The `ssh` session completes and drops you into a shell as `testuser`.

## What to look at while it runs

- `docker compose -f deploy/compose/compose.yaml logs broker` — one JSON line per state transition (`session_started`, `identity_bound`, `approved`, `consumed`), with `severity` set on each.
- The approval page's requester context line — it names the SSH client's host, which is the whole point (see `docs/threat-model.md`, check 3).

## How it's wired

- `deploy/compose/sshd/sshd_config`: `KbdInteractiveAuthentication yes`, `PasswordAuthentication no`, `PubkeyAuthentication no`, `AuthenticationMethods keyboard-interactive`, `UsePAM yes`.
- `deploy/compose/sshd/pam-sshd`: the `auth` step is `pam_exec.so quiet stdout /usr/local/bin/xdauth-pam http://host.docker.internal:8080` — its stdout reaches the client through the keyboard-interactive prompt; its exit code is the auth decision. The broker URL is a static argument, not an environment variable: sshd strips its own daemon environment before invoking PAM, so `XDAUTH_BROKER_URL` would rarely reach the helper that way.
- `cmd/xdauth-pam`: reads the broker URL from `argv[1]` (falling back to `XDAUTH_BROKER_URL` for manual testing) and `PAM_USER` as `login_hint`; fails closed on any error.

## Reusing this for your own IdP

Swap `dex` for your real provider: set `XDAUTH_ISSUER_URL`, `XDAUTH_CLIENT_ID`, `XDAUTH_CLIENT_SECRET`, and `XDAUTH_IDENTITY_CLAIM` on the `broker` service to match. See the README's "Provider notes" for Entra-specific advice (the UPN vs. on-prem account name mismatch).
