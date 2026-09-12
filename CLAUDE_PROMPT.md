# Claude Code prompt — build the xdauth MVP

Paste everything below the line into a fresh Claude Code session in an empty directory that contains `README.md` (the RFC). It is self-contained; it does not depend on any other environment.

---

Build the MVP of `xdauth`, the project described in ./README.md. Read the README first — it is the spec. Do not change its design; if something in it is ambiguous, pick the more conservative security option and say so.

## Scope of this MVP

Three deliverables, in this order. Stop after each and summarise before starting the next.

1. **`cmd/xdauth-broker`** — the broker server.
2. **`pkg/client`** — the Go client library, plus `cmd/xdauth-login`, a tiny reference CLI that uses it.
3. **`cmd/xdauth-pam`** — the PAM helper for stock OpenSSH via `pam_exec`, plus a working `docker-compose` demo with `sshd`.

Explicitly out of scope for now: SSH certificate issuance, a native (cgo) PAM module, Helm chart, any IdP-specific code beyond a generic OIDC provider. Do not add them.

## Language and layout

- Go, latest stable. Single module, `go.mod` at the root. Standard library first; allowed third-party deps: `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, a router if you want one (`chi` is fine), and a test assertion library. Justify anything else in a one-line comment in `go.mod`.
- Layout: `cmd/<binary>/main.go`, `internal/broker` (session state machine, checks, HTTP handlers), `internal/oidc` (provider wrapper), `internal/store` (session store interface + in-memory impl with TTL), `pkg/client`, `web/` (verification page templates, embedded with `embed`), `deploy/compose/` (dev environment), `docs/`.
- Config via flags + env vars (`XDAUTH_*`), never files with secrets committed. The IdP client secret comes only from env or a file path pointed to by env.

## Broker requirements (the part that matters)

Implement the endpoints from the README's sequence diagram:

- `POST /auth/start` — body `{login_hint, code_challenge, code_challenge_method:"S256", client_kind, client_host}`. Creates a session. Returns `{session_id, verification_uri, user_code, expires_in, interval}`. `user_code` is 8 characters from an unambiguous alphabet (no 0/O/1/I), formatted `XXXX-XXXX`. `verification_uri` points at THIS broker, never at the IdP.
- `GET /auth/verify/{session_id}` — starts Authorization Code + PKCE with the IdP (broker is the confidential client; broker generates its own PKCE pair and `state`/`nonce` for the IdP leg). Sets a secure, HttpOnly, SameSite=Lax cookie tying the browser to the session.
- `GET /auth/callback` — validates `state`, exchanges the code, verifies the ID token (issuer, audience, expiry, nonce, signature via JWKS), extracts the identity from a configurable claim (`XDAUTH_IDENTITY_CLAIM`, default `preferred_username`), binds it to the session, renders the approval page showing **client_host, client IP, client_kind, start time, and the identity**, with a field for the user code.
- `POST /auth/approve` — body `{user_code, decision: approve|deny}`. Constant-time compare of the code. Marks the session approved or denied.
- `POST /auth/poll` — body `{session_id, code_verifier}`. Returns `pending`, `approved {artifact}`, `denied`, or `expired`. The artifact for the MVP is `{subject, identity, claims, approved_at}`. Honour `interval`; return `slow_down` if polled faster.

The four checks must ALL pass before `approved` is ever returned, and they must be enforced in the state machine, not only in handlers:

1. `SHA256(code_verifier)` base64url == `code_challenge` from start.
2. `user_code` submitted on approve == the session's code (constant time, max 5 attempts then the session is denied).
3. Approval can only happen after the callback has bound an identity, and the approval page must have shown the requester context (template renders it unconditionally; test that the template contains the fields).
4. Bound identity == `login_hint` (case-insensitive; configurable normaliser hook for things like UPN vs sAMAccountName).

Session rules: single-use (any terminal state is final; a second poll after `approved` returns `expired`), TTL default 300s, per-IP and per-`login_hint` rate limits on `/auth/start` (token bucket, sane defaults, configurable), all secrets zeroed or never stored (store the challenge, never the verifier). Log every state transition as structured JSON with a `severity` field, never log codes, verifiers, tokens, or the client secret.

Security hygiene on the web side: CSRF token on the approve form, strict CSP, no inline JS, `Cache-Control: no-store` on every auth page, cookies as above. The verification page must also render correctly with JavaScript disabled.

## Client library and reference CLI

`pkg/client`: `Start(ctx, StartRequest) (*Session, error)` generates the PKCE pair internally and never exposes the verifier to callers beyond `Session`; `Poll(ctx, *Session) (*Result, error)` implements the interval/slow_down loop. `cmd/xdauth-login` prints the verification URI and user code, polls, and prints the artifact as JSON. Support `XDAUTH_BROKER_URL` and `--login-hint`.

## PAM helper

`cmd/xdauth-pam` is a plain binary invoked by `pam_exec.so stdout` from the sshd PAM stack. It reads `PAM_USER` as the login hint, calls the broker via `pkg/client`, prints the verification URI + code to stdout (pam_exec's `stdout` option forwards it to the user through keyboard-interactive), polls, and exits 0 on approval / non-zero otherwise. It must fail closed on any error and never fall back. Provide `deploy/compose/` with: the broker, a mock OIDC provider (dex is fine, with a static test user), and an `sshd` container configured with `KbdInteractiveAuthentication yes`, `UsePAM yes`, `PasswordAuthentication no`, and a PAM stack using the helper. The demo must be runnable with one command and documented in `docs/ssh-demo.md`.

## Tests — this is the headline deliverable, not an afterthought

- Unit tests for the session state machine covering every transition and every terminal state.
- **Phishing scenario tests** in `internal/broker/phishing_test.go`: an attacker starts a session; a victim completes the IdP login and approves. Assert the attacker's poll can never return `approved` when: (a) the attacker lacks the verifier; (b) the victim enters no/wrong code; (c) the victim's identity differs from the attacker's `login_hint`; (d) the session has expired; (e) the session was already consumed. Then assert the legitimate end-to-end path DOES succeed. These tests are the project's proof and must be named so a security reviewer can find them.
- An integration test that runs the broker against a mock OIDC provider (dex or an httptest-based OIDC server) end to end.
- `go vet`, `golangci-lint`, `govulncheck`, and `gosec` clean. Add a GitHub Actions workflow running all of it plus the compose demo smoke test.

## Repo hygiene

- `README.md` stays as the RFC; add `docs/architecture.md` (what you built, one page), `docs/threat-model.md` (start from the README's Security posture list and make it concrete), `SECURITY.md` with a disclosure policy placeholder, `LICENSE` (Apache-2.0), `CONTRIBUTING.md`.
- Conventional commits, one line each. No AI attribution lines in commits.
- Do not create a release; do not publish an image. Leave `goreleaser`/`cosign` for a later task, but structure `cmd/` so that is straightforward.

## Acceptance

1. `docker compose -f deploy/compose/compose.yaml up` gives me a broker, a mock IdP, and an sshd. `ssh testuser@localhost -p 2222` prints a URL and code; I open the URL in a browser, log in to the mock IdP, see the requester context, enter the code, and the SSH session is granted. `PasswordAuthentication` is off throughout.
2. `xdauth-login --login-hint testuser` does the same from a shell and prints the artifact.
3. `go test ./...` passes, and `phishing_test.go` demonstrably fails if I comment out any one of the four checks (add a short note in `docs/threat-model.md` explaining how to verify this).
4. Nothing in logs, artifacts, or the browser ever contains a verifier, a user code after approval, an IdP token, or the client secret.
