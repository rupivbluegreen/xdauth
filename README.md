# xdauth — phishing-resistant cross-device login for headless and air-gapped hosts

> **Status: RFC / pre-alpha.** Working name; nothing is released yet. Feedback wanted on the design before code lands.

`xdauth` lets a CLI, an SSH session, or any other non-browser client log in to an OpenID Connect **or SAML 2.0** identity provider (Microsoft Entra ID, Okta, Keycloak, Ping, ADFS, …) **without ever handling a password** and **without the phishing weakness of the OAuth 2.0 Device Authorization Grant (RFC 8628)**. The host running the client needs no internet access at all — only the user's browser does.

It is one small broker service, a client library, and a PAM helper for stock OpenSSH.

## The problem

Non-browser clients on servers, jump hosts, air-gapped VMs and CI runners have exactly three ways to authenticate a *human* against a modern IdP, and all three are bad:

| Option | Why it fails |
|---|---|
| **ROPC** (client collects the password and forwards it to the IdP) | Rejected by every IdP once MFA / Conditional Access is on (Entra returns `AADSTS50076`). It also turns your app into a credential-harvesting middleman. Removed from OAuth 2.1. |
| **Device Authorization Grant** (RFC 8628, `--device-code`) | Structurally phishable: the code is **not bound to the client that requested it**, and the IdP's consent page shows the user **nothing about who requested it**. An attacker starts the flow, sends the victim the code, the victim logs in legitimately (MFA included), the attacker gets the token. This is not theoretical — see Microsoft's Feb-2025 advisory on Storm-2372, and Microsoft now recommends *blocking* the flow via Conditional Access unless explicitly required. Security teams have started saying no. |
| **CIBA** (IdP pushes an approval to the user's enrolled authenticator) | The right standards answer, but not offered by several major IdPs (Entra among them), and it requires every user to have a push-capable authenticator — which on-prem and air-gapped organisations frequently don't. |

Meanwhile the browser-based tools (oauth2-proxy, Pomerium, Authelia) solve a different problem: they protect *web apps*, and require the browser and the app session to be the same thing. They cannot help a shell on a box with no internet.

## The idea

Keep the good part of RFC 8628 — the user authenticates in a browser on *any* device, so the host needs no egress — and fix the two structural gaps by **owning the verification page instead of sending users to the IdP's device-login page**.

The client runs a standard **Authorization Code + PKCE** flow *by proxy* through the broker, and the broker releases the result only when four independent bindings all hold:

1. **PKCE** — the client presents the `code_verifier` matching the `code_challenge` it sent at start. This binds the outcome to the process that initiated it. An attacker who tricks a victim into approving a session still cannot collect it.
2. **Number matching** — the person in the browser must type the short code displayed on the client's terminal. A victim approving an attacker-initiated session has no code to enter.
3. **Requester context** — before approving, the browser page shows *what* is asking: client hostname, source IP, client kind, start time. The user approves *that*, not an anonymous "sign in to App X".
4. **Identity match** — the identity the IdP returns must equal the `login_hint` the client sent. A session started for `alice` cannot be completed by `mallory`.

Sessions are single-use, short-lived (default 5 minutes), and rate-limited per source and per hint. This is the mitigation set recommended by the IETF *Cross-Device Flows: Security Best Current Practice* (draft-ietf-oauth-cross-device-security), packaged so you don't have to build it yourself.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (CLI / sshd via PAM)
    participant B as xdauth broker
    participant U as User's browser (any device)
    participant I as OIDC provider

    C->>B: POST /auth/start {login_hint, code_challenge, client_kind, client_host}
    B-->>C: {session_id, verification_uri, user_code, expires_in, interval}
    C->>U: shows verification_uri + user_code (terminal / keyboard-interactive prompt)
    U->>B: GET /auth/verify/{session_id}
    B->>I: Authorization Code + PKCE (broker is a confidential client)
    I->>U: normal login, MFA, Conditional Access
    I->>B: GET /auth/callback?code=…
    B->>B: validate ID token (issuer, audience, nonce, JWKS); bind identity to session
    B-->>U: "Approve login for alice from host-42 (10.1.2.3) at 10:32? Enter the code on your terminal"
    U->>B: POST /auth/approve {user_code}
    loop every `interval`
        C->>B: POST /auth/poll {session_id, code_verifier}
        B-->>C: pending | approved {artifact} | denied | expired
    end
```

The host running the client only ever talks to the broker. The broker is the only component that needs a route to the IdP.

## Components

| Piece | What it is | Status |
|---|---|---|
| `xdauth-broker` | The server. Go, single static binary, container image. Speaks OIDC (Authorization Code + PKCE) or SAML 2.0 (SP-initiated, `internal/saml`) to your IdP — the protocol is behind an `IdentityProvider` interface, so the session state machine and the four checks are identical either way. Owns sessions, the verification page, and the four checks. | built |
| `pkg/client` | Go library: `Start` / `Poll` with PKCE handled for you. Add xdauth login to a CLI in ~20 lines. | built |
| `xdauth-pam` | Helper for stock OpenSSH: `sshd` → `pam_exec` → helper prints the URL + code through keyboard-interactive, polls the broker, exits 0 on approval. No custom SSH client, no cgo. Known limitation: `pam_exec`'s relay is not guaranteed live — see `docs/ssh-demo.md`. | built |
| `xdauth-sshd` | Recommended SSH integration: a custom server on `golang.org/x/crypto/ssh` using `KeyboardInteractiveCallback` directly, so the prompt is written to the wire immediately instead of relayed through `pam_exec`'s stdout. See `docs/gossh-server.md`. | built |
| `xdauth-pam-native` | Attempt at a native (cgo) PAM module to fix `xdauth-pam`'s relay limitation while keeping stock `sshd`. Loads and runs correctly up to the broker call, which hangs unresolved in testing. Not recommended; see `docs/native-pam-status.md`. | experimental, not working |
| SSH certificate issuer | Optional: on approval the broker signs a short-lived SSH certificate (principals = identity) so the user is prompted once and then uses plain `ssh` freely. | later |
| Kubernetes / Helm | Deployment chart, PDB, metrics. | later |

## What the client gets back

The broker never hands IdP tokens to the client. On approval it returns an **artifact** chosen by configuration:

- an `id` object (subject, claims) for the caller to mint its own session/JWT — the default, and what a CLI backend normally wants;
- a broker-signed JWT, if you don't have your own issuer;
- an SSH certificate (see above).

Keeping IdP tokens inside the broker keeps their blast radius small and makes revocation a broker-side concern.

## Provider notes

Any OIDC provider works, and so does any SAML 2.0 IdP (`--protocol=saml`: `XDAUTH_SAML_IDP_METADATA_URL` or `_FILE`, optional `XDAUTH_SAML_IDENTITY_ATTRIBUTE` — defaults to the assertion's `NameID`). Optional `XDAUTH_SAML_ENTITY_ID` and `XDAUTH_SAML_ACS_URL` let the SP's entity ID and ACS URL be overridden independently of `XDAUTH_BASE_URL`, e.g. when migrating from an existing SP already registered with the IdP under different values. Two things are worth doing on the IdP side regardless of vendor or protocol:

- **Scope the flow.** Allow this pattern only for the broker's app registration and block other device/cross-device flows tenant-wide (Entra: Conditional Access → *Authentication flows*).
- **Require phishing-resistant authentication** (FIDO2 / passkeys / platform authenticators) and managed devices for the broker app. The broker makes the *cross-device step* safe; the IdP still owns the *primary* authentication.

**Microsoft Entra ID, hybrid tenants:** the OIDC ID token's `preferred_username` is the UPN; the SAML `NameID` commonly is too. If your systems key on the on-prem AD account name, add `onPremisesSamAccountName` as an optional ID-token claim (OIDC) or attribute (SAML) on the app registration and have the broker read that (`XDAUTH_IDENTITY_CLAIM` / `XDAUTH_SAML_IDENTITY_ATTRIBUTE`). Doing this once in the broker saves every consumer an LDAP round-trip.

**Protocol binding equivalents.** SAML has no PKCE or nonce, but plays the same binding roles differently: the broker's `RelayState` carries the session id (checked against the browser's session cookie, same as OIDC's `state`), and the assertion's `InResponseTo` is checked against the broker's own `AuthnRequest` ID (the same role OIDC's `nonce` plays against replay). Checks 2–4 (number matching, requester context, identity match) are implemented once in `internal/broker` and apply identically to both protocols.

## Non-goals

- Replacing your IdP's primary authentication or MFA.
- Being a general web reverse proxy — use oauth2-proxy / Pomerium for that.
- Machine-to-machine auth (use client credentials / workload identity).
- Supporting ROPC or unmodified RFC 8628 as a "compat" mode. That would recreate the problem this project exists to fix.

## Security posture

This is an authentication component; a bug here is a credential compromise. Before a 1.0:

- a written threat model (attacker-initiated session, code interception, replay, token theft from the broker, malicious client host, compromised verification page);
- a **phishing test suite in CI** that proves the headline claim: an attacker-initiated session cannot be completed by a victim, under every combination of the four checks being individually bypassed;
- independent review of the broker;
- signed releases (Sigstore/cosign), SBOM, reproducible container builds;
- a security disclosure policy.

## Comparison

| | Password sent to IdP | Client-bound | User sees requester context | Works air-gapped | Stock SSH client | IdP support needed |
|---|---|---|---|---|---|---|
| ROPC | yes | – | – | yes | yes | blocked by MFA |
| RFC 8628 device code | no | **no** | **no** | yes | yes (via PAM) | broad |
| CIBA | no | yes | yes | yes | yes | **rare** |
| oauth2-proxy / Pomerium | no | yes | n/a | **no** | n/a | broad |
| Teleport / similar | no | yes | yes | partial | **no** | broad |
| **xdauth** | no | yes | yes | yes | yes | any OIDC or SAML 2.0 |

## Roadmap

1. RFC feedback (this document).
2. `xdauth-broker` MVP + `pkg/client` + phishing test suite + local dev environment with a mock IdP.
3. `xdauth-pam` helper and an end-to-end OpenSSH demo.
4. ~~SAML 2.0 support~~ (`internal/saml`, `--protocol=saml`); Entra and Keycloak provider guides; Helm chart.
5. Threat model + external review → 1.0.
6. SSH certificate artifact; native PAM module.

## Contributing / feedback

Open an issue against this RFC — especially if you run headless or air-gapped hosts and have been told "device code is not acceptable." Tell us what your IdP is and what your security team would need to see.

License: Apache-2.0 (proposed).
