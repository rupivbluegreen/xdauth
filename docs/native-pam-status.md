# Native PAM module — status: unresolved, not recommended yet

`cmd/xdauth-pam-native` is an experiment, not a finished component. This page records what was tried and why it isn't the recommended path today — see `docs/gossh-server.md` for the approach that actually works.

## Why it was attempted

`docs/ssh-demo.md`'s `pam_exec`-based demo has a real limitation: `pam_exec.so`'s `stdout` relay does not deliver messages to the SSH client live. A test proved it directly — a script that does `echo hello; sleep N` only shows "hello" to the client right as the sleep ends, not when it's printed. That breaks the "show the code immediately, then wait minutes for approval" UX xdauth needs.

The fix in theory: a **native PAM module** calls PAM's `conv()` function directly, in-process, in the same call that's already blocked — no exec, no pipe, no relay layer to introduce delay. This is how production PAM+OTP integrations (Duo, RSA SecurID, etc.) actually work, and it's what this project's own roadmap calls "a native PAM module" as the eventual fix.

## What was built

`cmd/xdauth-pam-native/pam_module.go`: a real cgo PAM module (`go build -buildmode=c-shared`), exporting `pam_sm_authenticate`/`pam_sm_setcred`, reading the broker URL from a static pam.d module argument (not an environment variable — `sshd` does not reliably forward its own process environment into PAM), reading the login hint via `pam_get_user`, and sending a `PAM_TEXT_INFO` message via a small C helper that calls `conv->conv(...)` directly.

Confirmed working, via a temporary file-based trace log:
- The module loads correctly into `sshd`'s PAM stack (`/etc/pam.d/sshd` pointing at the built `.so`).
- `pam_get_user`, `pam_get_item(PAM_CONV)`, and the module-argument parsing all succeed.
- Execution reaches the point of calling `pkg/client.Start` (the broker HTTP call).

## What didn't work

The outbound HTTP call to the broker hung indefinitely from inside the module, in a Docker Compose test environment (Debian bookworm-slim, OpenSSH 9.2/9.6). Isolating further: even a bare `net.DialTimeout` to a raw IP address — no DNS, no HTTP, nothing but a TCP connect — also hung in at least one run, while the identical dial from a plain `docker exec` shell in the same container succeeded instantly.

That inconsistency doesn't point cleanly at one cause. Candidates considered but not confirmed:
- A container/seccomp-specific restriction on the process context PAM authentication runs in (plausible, but a blocked syscall would normally fail fast, not hang).
- A Go-runtime-in-cgo-embedded-in-a-multithreaded-host interaction (Go's runtime being invoked via `-buildmode=c-shared` from threads it didn't create) — a known general class of subtlety, not confirmed as the specific cause here.
- Confounding from the test environment itself: this was diagnosed while multiple concurrent editors were rebuilding the same Docker images and Compose files, which is not a clean environment for this kind of low-level, timing-sensitive debugging.

## Recommendation

Use `xdauth-sshd` (`docs/gossh-server.md`) instead. It solves the same problem — live prompt delivery, no `pam_exec` relay — with a mechanism that has an actual passing test proving the property (`TestKeyboardInteractive_ChallengeDeliveredBeforeApproval`), and it avoids the entire native-PAM/cgo/sshd-internals problem space by not going through PAM or `sshd` at all: the SSH server is xdauth's own code.

If you want to pick this back up: reproduce on a real (non-containerized) Linux host running `sshd` directly, to rule out container networking/seccomp as a variable, and add the same kind of file-based tracing this investigation used (stdout/stderr are not reliably visible from inside a loaded PAM module) before touching the networking code again.
