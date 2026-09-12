# Custom Go SSH server demo

`cmd/xdauth-sshd` is a second reference integration for SSH, alongside the PAM demo in `docs/ssh-demo.md`: a minimal SSH server built directly on `golang.org/x/crypto/ssh`, using `ssh.ServerConfig.KeyboardInteractiveCallback` as the only accepted auth method (no password, no public key).

## What this demonstrates

The PAM demo (`cmd/xdauth-pam`, invoked by `sshd` through `pam_exec`) has a real, structural limitation: `pam_exec`'s `stdout` relay to the SSH client does not stream live. A message the helper prints only reaches the client once the helper process exits, because `sshd` reads the exec'd process's stdout and forwards it through PAM's own conversation function on its own schedule, not as each line is written. For a flow that must show a URL and code *immediately* and then block for minutes waiting on approval, that is a bad trade: on some platforms the message reliably shows up only once the helper exits, i.e. once the whole login has already succeeded or failed.

This demo has no such relay to reason about. There is no exec'd helper and no stdout pipe: `KeyboardInteractiveCallback` runs in-process inside the SSH server, and the `challenge(instruction, questions, echos)` function it's given *is* the wire write — calling it sends an SSH `SSH_MSG_USERAUTH_INFO_REQUEST` down the same connection immediately, synchronously, before the callback goes on to block on anything else. `cmd/xdauth-sshd/main.go`'s `keyboardInteractiveAuth` calls `challenge(...)` with the verification URL and code right after `client.Start` returns, and only calls the blocking `client.Poll` afterwards — so the client sees the prompt before the broker has even had a chance to approve the session.

`cmd/xdauth-sshd/main_test.go`'s `TestKeyboardInteractive_ChallengeDeliveredBeforeApproval` proves this against a real `golang.org/x/crypto/ssh` client over a loopback TCP connection: a fake broker refuses to report the session as approved until the test has already observed the client receive the challenge, so the assertion isn't "the message eventually arrived" but "the message arrived while the session was still pending."

## Comparison with the PAM demo

| | `cmd/xdauth-pam` (PAM demo) | `cmd/xdauth-sshd` (this demo) |
|---|---|---|
| SSH server | stock OpenSSH | custom, `golang.org/x/crypto/ssh` |
| How the prompt is delivered | `pam_exec` execs a helper; its stdout is relayed to the client by `sshd`/PAM | `KeyboardInteractiveCallback`'s `challenge()` writes to the connection directly |
| Live delivery of the prompt | not guaranteed — can be held until the helper process exits | immediate, by construction |
| Auth decision | helper's process exit code | callback's return value |
| Client requirement | any SSH client (stock `ssh`, PuTTY, …) | any SSH client (stock `ssh`, PuTTY, …) |
| Extra moving parts | PAM stack, `pam_exec`, a separate binary | none — one Go binary |
| When to use | you must keep stock `sshd` (existing fleet, existing PAM policy) | you control the SSH server itself and want simpler, provably-live prompt delivery |

The PAM demo's limitation is a reasonable MVP trade-off, not a bug: it lets xdauth gate logins on stock OpenSSH with no changes to the SSH server itself. This demo shows the alternative for anyone who can run their own SSH server instead.

A third option, a **native PAM module** that calls PAM's conversation function directly instead of relaying through `pam_exec`, was also attempted as a way to keep stock `sshd` *and* get live delivery — see `docs/native-pam-status.md` for why that one is not recommended yet.

## Run it

Standalone:

```sh
go run ./cmd/xdauth-broker --base-url http://localhost:8080   # in one terminal, plus its usual OIDC/SAML env vars
go run ./cmd/xdauth-sshd --broker-url http://localhost:8080   # in another; listens on :2323 by default
```

Or as part of the compose demo (same `dex` mock IdP as `docs/ssh-demo.md`, on a Linux Docker host):

```sh
docker compose -f deploy/compose/compose.yaml up --build xdauth-sshd
```

Either way, from another terminal:

```sh
ssh -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no -p 2323 alice@localhost
```

You'll see the same verification URL + code prompt as the PAM demo, immediately, before the connection blocks waiting for approval. Approve it in the browser the same way, and the demo drops a single message into a trivial fixed "shell" (this is a reference example for the auth pattern, not a full SSH gateway — no port forwarding, no SFTP, no real shell).

## Configuration

Flags with environment fallbacks, matching the rest of the project's `XDAUTH_*` convention:

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--listen` | `XDAUTH_SSHD_LISTEN_ADDR` | `:2323` | address to listen on |
| `--broker-url` | `XDAUTH_BROKER_URL` | (required) | the xdauth broker's base URL |
| `--host-key-file` | `XDAUTH_SSHD_HOST_KEY_FILE` | (unset) | path to an SSH host private key; an ephemeral ed25519 key is generated per process if unset |
| `--shell-message` | `XDAUTH_SSHD_SHELL_MESSAGE` | a demo string | message printed in the trivial demo session |

An ephemeral host key means the client will see a host-key-changed warning on every restart; pass `--host-key-file` for anything longer-lived than a one-off demo.
