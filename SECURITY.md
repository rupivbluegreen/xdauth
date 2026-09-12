# Security Policy

xdauth is an authentication component; a bug here can mean a credential or identity compromise. Please report privately, not via a public issue.

## Reporting a vulnerability

Open a [GitHub Security Advisory](../../security/advisories/new) on this repository (Security tab → "Report a vulnerability"). If that's not available to you, open an issue titled "security contact needed" with no details, and we'll follow up privately.

Please include: the affected version/commit, a description of the issue, and — if possible — steps to reproduce or a proof of concept. We're pre-1.0, so there's no bug bounty, but we will credit reporters in the advisory unless you ask us not to.

## Scope

In scope: `xdauth-broker`, `pkg/client`, `xdauth-pam`, and the verification/approval web pages. Particularly interested in anything that lets an attacker-initiated session be completed by a victim — that is the one property this project exists to guarantee; see `docs/threat-model.md`.

Out of scope: the demo `deploy/compose/` environment (uses a mock IdP and test secrets on purpose) and denial-of-service reports against the in-memory session store (a documented MVP limitation, not a vulnerability).

## Supported versions

Pre-1.0: only the latest commit on `main` is supported. There is no release yet.
