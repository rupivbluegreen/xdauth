# RFC 10027 compliance

[RFC 10027](https://datatracker.ietf.org/doc/rfc10027/) (BCP 247, *Best Current Practice for Security of Cross-Device Flows*, August 2026) is the finalized version of the IETF draft the README and threat model already cite as this project's design basis. It names two attack classes — **CDCP** (Cross-Device Consent Phishing, exploiting the unauthenticated channel between the device starting the flow and the device approving it) and **CDSP** (Cross-Device Session Phishing, tricking a user into forwarding a session-transfer code) — and lists 18 mitigations in §6.1, plus protocol selection guidance in §6.2. This page maps every mitigation against what `xdauth` actually does, so a reviewer doesn't have to take the README's word for it.

## §6.2 protocol selection: where xdauth sits

RFC 10027 recommends, in order: FIDO2/WebAuthn (proximity-based, via BLE) as the preferred approach "when feasible"; the Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) and CIBA for constrained-input devices, both flagged as needing the §6.1 mitigations layered on top since neither is proximity-based on its own.

`xdauth` targets exactly the case where FIDO2's proximity model doesn't apply: a headless SSH host or CI runner and the user's phone/laptop are typically not in the same room, let alone BLE range — that's the whole point of "air-gapped." So it takes the RFC's second-choice path (Device Authorization Grant's shape) and applies the §6.1 mitigation set itself, rather than relying on the IdP or leaving it to the implementer as RFC 8628 does. This is the intended use of the BCP, not a shortcut around it.

## §6.1 mitigations, one by one

| # | Mitigation | Status | Where |
|---|---|---|---|
| 1 | Establish proximity | **Not implemented** | Structural gap, not an oversight — see below. |
| 2 | Short-lived / time-bound codes | **Yes** | `SessionTTL`, default 5 minutes (`broker.go` `applyDefaults`). |
| 3 | One-time / limited-use codes | **Yes** | `poll()` consumes an approved session exactly once (`TestPoll_ApprovedIsSingleUse`); `approve()` is only valid from `AwaitingApproval`. |
| 4 | Unique codes | **Yes** | Session id and user code are freshly random per `newSession` call; never derived from client input. |
| 5 | Content filtering | **N/A** | Nothing here forwards the code/URL through a message channel `xdauth` controls — the user types the `verification_uri`/code themselves from the terminal. Relevant only if a caller chooses to email or SMS it, which is outside this project. |
| 6 | Detect and remediate | **Partial** | Rate limiting (below) bounds abuse; there's no anomaly detection or automatic revocation of already-issued artifacts. Listed as a known gap, not claimed as done. |
| 7 | Trusted devices | **Not implemented** | No device registration/allowlisting; any client can call `/auth/start`. |
| 8 | Trusted networks | **Not implemented** | `client_ip`/`client_host` are shown to the approver as context (check 3) but never used to allow or deny. |
| 9 | Limited scopes | **N/A to this layer** | The broker hands back an identity artifact, not an OAuth-scoped access token; scope limiting is the consuming application's job once it mints its own session/JWT. |
| 10 | Short-lived tokens | **Partial** | The *session* is short-lived (mitigation 2). The *artifact* xdauth returns has no built-in expiry of its own today — the only artifact with an inherent lifetime is the not-yet-built SSH certificate (README roadmap item 6). |
| 11 | Rate limits | **Yes** | Per-IP and per-`login_hint` token-bucket limiters on `/auth/start` (`ipLimiter`/`hintLimiter`, default 1 per 5s, burst 5). |
| 12 | Sender-constrained tokens | **Yes, via check 1** | PKCE (`code_verifier`/`code_challenge`) binds the approved result to the process that started it — the cross-device-flow equivalent of sender constraint, enforced in `poll()`. |
| 13 | User education | **Out of scope for code**, addressed in docs | README "Provider notes" and this doc exist partly for this reason. |
| 14 | User experience: clear context | **Yes — this is check 3** | The approval page always shows client host, IP, kind, and start time before a decision is possible (`TestApproveTemplate_AlwaysShowsRequesterContext`). |
| 15 | Authenticate then initiate | **Not implemented** | The client that calls `/auth/start` is unauthenticated and self-reports `client_host`/`client_kind`; nothing requires it to already hold credentials before starting a session. Compensated for, not satisfied, by identity match (check 4) at the end. |
| 16 | Request initiation verification | **Yes — checks 2 + 3 together** | Number matching proves the approver is looking at the same terminal that started the request; requester context lets them notice if it isn't theirs. |
| 17 | Request binding with out-of-band data | **Yes — this is check 1 again** | PKCE's `code_verifier` is exactly "out-of-band data the legitimate party can prove possession of." |

This table was built from a summarized read of §6.1, not the raw RFC text — treat the mitigation count and exact wording as approximate, and re-verify against the published text before relying on this for a compliance sign-off.

## The one real gap: proximity

Mitigation 1 (and the RFC's overall preference for FIDO2/WebAuthn) assumes the two devices *can* be near each other and that proximity is a meaningful signal. For `xdauth`'s target scenario — a cloud SSH host, CI runner, or air-gapped VM being approved from a phone that could be anywhere — proximity isn't just unimplemented, it's usually not a coherent concept to enforce. This is a genuine, acknowledged limitation relative to the RFC's top recommendation, not something a future release will "fix": if proximity between the client host and the approving device is available and meaningful in your deployment, prefer FIDO2/WebAuthn hybrid transport over this project entirely, per the RFC's own §6.2 guidance.

## Net assessment

Of the 17 mitigations reviewed, `xdauth` implements 8 fully (2, 3, 4, 11, 12, 14, 16, 17), has 2 partial (6, 10), has 3 not applicable to a broker at this layer (5, 9, 13), and has 3 structural gaps (1, 7, 8) plus one design tension inherited from targeting headless/air-gapped hosts (15). The four checks in `docs/threat-model.md` map cleanly onto the RFC's own highest-leverage mitigations (unique/one-time codes, sender-constrained binding, request initiation verification, clear UX) — this project didn't invent a new approach, it's an implementation of what BCP 247 already recommends for exactly this constrained-input, no-proximity case.
