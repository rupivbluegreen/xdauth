# Threat model

Starting point: the README's "Security posture" list. This page makes it concrete for the MVP as built.

## What this project defends against

**An attacker-initiated cross-device session being completed by a victim.** This is RFC 8628 device code's structural flaw (Storm-2372): the code isn't bound to the requester, and the consent page shows the victim nothing about who's asking. Everything below is in service of this one property.

## Attacker model

The attacker can: start sessions against the broker (`login_hint` of their choosing), send a victim a `verification_uri` and/or `user_code` by any channel (email, chat, phone call), observe the broker's public HTTP responses, and guess or brute-force session ids and codes at the rate the rate limiter allows. The attacker cannot: read the legitimate client's memory or network traffic (so never learns its PKCE `code_verifier`), or compromise the IdP itself.

## The four checks, and what each one closes

| # | Check | Where enforced | Attack it closes |
|---|---|---|---|
| 1 | PKCE: `SHA256(code_verifier)` == `code_challenge` | `poll()` in `session.go`, via `verifyClientPKCE` | Attacker starts a session, tricks a victim into approving it, then tries to poll the result themselves without ever having the verifier. |
| 2 | Number matching: submitted code == session's code, constant-time, max 5 attempts | `approve()` in `session.go` | Victim never sees a code to enter unless they're actually completing the attacker's flow; brute force is capped. |
| 3 | Requester context shown before approval | `approve.html`, asserted unconditionally in `templates_test.go` | A victim who is shown "sign in as X from Y at Z" has a chance to notice this isn't their own request. |
| 4 | Identity match: IdP identity == `login_hint`, checked immediately in `bindIdentity` | `session.go`, enforced before the state ever reaches `awaiting_approval` | Attacker starts a session for `alice`, sends it to `mallory`; if `mallory` logs in as herself, the session denies itself before an approval page is even reachable — closing the gap even if checks 2/3 were somehow bypassed. |

`internal/broker/phishing_test.go` has one test per row (plus the legitimate path and replay/expiry), named so a reviewer can find them without reading the rest of the codebase. All four checks live in `internal/broker` and run identically regardless of protocol — SAML's `RelayState`/`InResponseTo` and OIDC's `state`/`nonce`/PKCE are protocol-specific correlation mechanisms each `IdentityProvider` validates internally (see `docs/architecture.md`), but neither can produce an `approved` result without also passing checks 1–4.

## How to verify this yourself

Comment out one check at a time and watch the corresponding phishing test fail:

- Comment out the `verifyClientPKCE` call in `poll()` → `TestPhishing_AttackerLacksVerifier` fails (poll returns approved without the real verifier).
- Comment out the attempt-counting in `approve()` → `TestPhishing_VictimEntersWrongCode` still passes, but unlimited brute force stops being tested (add a loop bound test if you do this).
- Comment out the `normalize(...) != normalize(...)` check in `bindIdentity` → `TestPhishing_VictimIdentityDiffersFromLoginHint` fails.
- Remove a field from `approve.html` → `TestApproveTemplate_AlwaysShowsRequesterContext` fails.

## Client authentication (mitigations 7, 15)

`/auth/start` is open by default (demo/local dev). Setting
`XDAUTH_CLIENT_AUTH_TOKENS` (`token=client_id,...`) or wiring
`broker.MTLSClientAuth` requires the caller to authenticate before a
session is created, and the verified client id is shown on the approval
page distinct from the self-reported `client_host`.

## Trusted networks and client IP (mitigation 8)

`resolveClientIP` (`internal/broker/clientip.go`) trusts `X-Forwarded-For`
only from peers in `XDAUTH_TRUSTED_PROXIES`; behind an untrusted or
unconfigured proxy every client previously collapsed into one rate-limit
bucket keyed on the proxy's own address. `XDAUTH_ALLOWED_CLIENT_CIDRS`
optionally restricts `/auth/start` to specific networks.

## Detect and remediate (mitigation 6)

Wrong codes, identity mismatches, repeated `/auth/start` for one `login_hint`,
and replayed polls of a consumed session are counted per key; a threshold
trip logs `suspected_abuse` and, if `XDAUTH_ABUSE_WEBHOOK_URL` is set, POSTs
a `SecurityEvent` (never a code, verifier, or token) to it. See
`internal/broker/detect.go`.

## Known gaps in this MVP

- **In-memory session store.** A broker restart loses all in-flight sessions (they just have to be restarted by the client) and a multi-replica deployment needs a shared store this MVP doesn't provide — see `docs/architecture.md`.
- **No independent review yet.** This is one implementer's read of the IETF Cross-Device Flows BCP; treat it as such until reviewed.
- **Session store is not encrypted at rest** (it's in-memory, so "at rest" doesn't quite apply, but a future Redis-backed store should encrypt or at least not persist the `code_challenge`/`user_code` longer than the TTL).
- **Rate limiting is per-broker-process**, not shared across replicas.
- **No signed releases, SBOM, or reproducible builds yet** — see the README roadmap.

## What is explicitly not this project's job

Primary authentication and MFA strength are the IdP's job (see README "Provider notes" — require phishing-resistant auth and managed devices for the broker app at the IdP). This project only makes the *cross-device* step safe.
