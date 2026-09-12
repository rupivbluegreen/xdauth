# Contributing to xdauth

Thanks for looking at this. It's pre-alpha and the design in `README.md` is still an RFC, so the most valuable contribution right now is feedback on the design, not code.

## How to contribute

- **Design feedback**: open an issue. Tell us your IdP, your client population (headless? air-gapped? CI?), and what your security team has said about device code or ROPC.
- **Bug reports**: include Go version, OS, and the exact command/request that failed.
- **Pull requests**: keep them scoped to one change. Run `go build ./...`, `go vet ./...`, `golangci-lint run`, and `go test ./...` before opening.

## Code conventions

- Go, latest stable, formatted with `gofmt`.
- Comments are one line each — no multi-line comment blocks.
- Commit messages: Conventional Commits, one line each, no AI attribution.
- New third-party dependencies need a one-line justification comment in `go.mod`.

## Security-critical code

`internal/broker` is the trust boundary. Any change there needs:

- A unit test for the new/changed state transition.
- If it touches one of the four checks (PKCE, number matching, requester context, identity match), a new case in `internal/broker/phishing_test.go` proving the attack it closes.

See `docs/threat-model.md` before touching this package.

## Reporting a vulnerability

See `SECURITY.md` — please don't open a public issue for a security bug.
