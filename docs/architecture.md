# Architecture

What's actually built, as of this MVP. The design rationale lives in the root `README.md`; this page is the "what", not the "why".

## Packages

| Package | Role |
|---|---|
| `internal/store` | The `Session` model and the `Store` interface; `Memory` is the only implementation, with TTL sweeping. |
| `internal/oidc` | The broker's own confidential-client Authorization Code + PKCE exchange with the upstream IdP, via `coreos/go-oidc`. |
| `internal/saml` | The broker's SP-initiated SAML 2.0 leg with the upstream IdP, via `crewjam/saml`. Alternative to `internal/oidc`, selected by `--protocol`. |
| `internal/broker` | The session state machine (`session.go`), the four checks, the HTTP handlers (`handlers.go`), rate limiting, and the embedded HTML templates. This is the trust boundary — see `docs/threat-model.md`. `idp.go`'s `IdentityProvider` interface is what lets it not know or care which protocol is in use. |
| `pkg/client` | `Start`/`Poll`, the public Go API any CLI or daemon can use. |
| `cmd/xdauth-broker` | The broker binary. |
| `cmd/xdauth-login` | A ~60-line reference CLI built on `pkg/client`. |
| `cmd/xdauth-pam` | The `pam_exec` helper for stock OpenSSH. |
| `web/` | Embedded HTML templates (`html/template`, no JavaScript). |

## The state machine

`internal/broker/session.go` is intentionally pure: every function takes a `*store.Session` and a clock (`time.Now()` passed in, not called internally), and returns an error or a result. The HTTP handlers in `handlers.go` are a thin adapter: decode the request, call the pure function, persist, respond. This is what makes `phishing_test.go` possible without spinning up HTTP at all.

States: `pending` → `awaiting_approval` → one of `approved` / `denied` / `expired` (terminal). See the `README.md` sequence diagram for which endpoint drives which transition.

## One IdentityProvider interface, two protocols

`internal/broker/idp.go` defines `BeginLogin(sess) (redirectURL, error)` and `CompleteLogin(ctx, r, sess) (store.Identity, error)`. `*oidc.Provider` and `*saml.Provider` both satisfy it directly (no adapter type needed) by storing whatever correlation data they need directly on the `*store.Session` fields added for that purpose (`IdPState`/`IdPNonce`/`IdPPKCEVerifier` for OIDC, `SAMLRequestID` for SAML). `handleVerify` and `handleIdPResponse` in `handlers.go` are entirely protocol-agnostic; only `/auth/callback` (GET, OIDC) vs `/auth/saml/acs` (POST, SAML) differ, and both route to the same handler.

## Two PKCE pairs, not one (OIDC only)

It's easy to conflate these:

- The **client's** PKCE pair (`code_challenge` sent at `/auth/start`, `code_verifier` sent at `/auth/poll`) binds the poll to the process that started the session. `internal/broker/pkce.go`. This exists for both protocols.
- The **broker's own** PKCE pair for its Authorization Code exchange with the upstream IdP, generated fresh per session in `oidc.Provider.BeginLogin` and never exposed to the client. `internal/oidc/oidc.go`'s `PKCEPair`. SAML has no equivalent of this second pair — its `AuthnRequest`/`InResponseTo` ID plays that binding role instead (see `saml.Provider.BeginLogin`/`CompleteLogin`).

## Cookies and CSRF

The browser side is bound to one session by an `HttpOnly` cookie set in `handleVerify` (before the IdP redirect) and read back in `handleIdPResponse` and `handleApprove`. `SameSite` is `None` (required for the SAML HTTP-POST binding, whose ACS callback is a cross-site POST that a `Lax` cookie never rides along on), falling back to `Lax` only when the request isn't HTTPS, since `SameSite=None` without `Secure` is dropped by browsers outright. `Secure` is set from the actual request (`r.TLS != nil` or `X-Forwarded-Proto: https`), not hardcoded — a hardcoded `Secure: true` would silently drop the cookie over plain HTTP, which is how the local dev/demo environment runs.

A separate per-session CSRF token, generated once identity is bound, is a hidden field in the approval form and checked in `handleApprove` — independent of the four phishing-resistance checks, this is ordinary web hygiene.

## Artifact lifetime

The `Artifact` `poll` releases carries its own `ExpiresAt` (default 120s from `Config.ArtifactTTL`, `XDAUTH_ARTIFACT_TTL_SECONDS`), independent of the session's own TTL (mitigation 10). Consumers should mint their own session on receipt, not persist the artifact.

## Shared session store

`internal/store.Redis` (`XDAUTH_REDIS_ADDR`) implements the same `Store` interface as `Memory`, verified against a shared conformance suite (`internal/store/conformance_test.go`), so a multi-replica broker deployment isn't limited to single-process `Memory`. Rate limiting (`internal/broker/ratelimit.go`) and the abuse detector (`internal/broker/detect.go`) remain per-process even with a Redis store — sharing those across replicas is tracked separately.

## What's not built yet

Everything in the README's "Components" table marked `later`: SSH certificate issuance, a native (cgo) PAM module, and a Helm chart.
