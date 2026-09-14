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

**Check 2 also requires the submitting browser to be the one that authenticated.** Number matching only closes the gap it claims to if the code can only be submitted from the browser that just completed the IdP login. A fixed bug let `GET /auth/verify/{id}` hand a valid session cookie to any browser once the session reached `awaiting_approval`, which meant an attacker who merely got a victim to *authenticate* (no code needed) could then approve from their own browser using the code they already held. `bindIdentity` now mints a per-browser secret at identity-bind time and `approve` requires it (`ErrApprovalNotBound`, `TestPhishing_ApprovalRequiresAuthenticatedBrowsersBinding`, `TestIntegration_UnauthenticatedBrowserCannotApprove`).

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

## Delegated proximity via required authentication method (mitigation 1)

`XDAUTH_REQUIRE_AMR` (`oidc.Config.RequiredAMR`) rejects any ID token whose
`amr` claim (RFC 8176) doesn't include a listed value, e.g. `hwk`/`swk` for
a FIDO2/WebAuthn credential. This delegates proximity verification to the
IdP entirely — xdauth never becomes a WebAuthn relying party — and is
meaningful only where the two devices genuinely can be near each other; it
does not apply to (and doesn't attempt to fix) the air-gapped core case.

## Detect and remediate (mitigation 6)

Wrong codes, identity mismatches, repeated `/auth/start` for one `login_hint`,
and replayed polls of a consumed session are counted per key; a threshold
trip logs `suspected_abuse` and, if `XDAUTH_ABUSE_WEBHOOK_URL` is set, POSTs
a `SecurityEvent` (never a code, verifier, or token) to it. See
`internal/broker/detect.go`.

## Known gaps in this MVP

- **In-memory session store is still the default**; `internal/store.Redis` is available for multi-replica deployments (`XDAUTH_REDIS_ADDR`) — see `docs/architecture.md`.
- **No independent review yet.** This is one implementer's read of the IETF Cross-Device Flows BCP; treat it as such until reviewed.
- **Session store is not encrypted at rest.** Neither `Memory` nor `Redis` encrypts the `code_challenge`/`user_code`; both rely on TTL expiry to bound exposure.
- **Rate limiting and the abuse detector are per-broker-process**, not shared across replicas, even when a shared `Redis` store is configured.
- **Releases aren't cut yet**, but the mechanism is in place: `.goreleaser.yaml` builds `xdauth-broker`/`xdauth-login`/`xdauth-pam`/`xdauth-sshd` reproducibly (`-trimpath`, commit-timestamped), generates an SPDX SBOM per archive, builds and signs the broker's multi-arch container image, and signs the checksums file — all via `.github/workflows/release.yml` on a `v*` tag push, using cosign's keyless (OIDC) signing so no long-lived signing key is stored in CI.

## What is explicitly not this project's job

Primary authentication and MFA strength are the IdP's job (see README "Provider notes" — require phishing-resistant auth and managed devices for the broker app at the IdP). This project only makes the *cross-device* step safe.
