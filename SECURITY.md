# Security Policy — Gatekeeper

## Supported versions

| Version | Supported |
|---|---|
| `1.x` (current, `version: "1.0.0"` in `handleHealthz`, `internal/api/api.go:207`) | ✅ Receives security fixes |
| `< 1.0` / pre-release snapshots | ❌ Not supported — upgrade |

## Reporting a vulnerability

Please report privately — do **not** open a public issue for a suspected
vulnerability. Contact the maintainers through a private security
advisory (GitHub "Report a vulnerability" on this repo) or the
maintainer channel listed in the repo. Include:

- Affected component (e.g. `internal/auth`, `internal/api`, `internal/store`),
- Steps to reproduce or a minimal PoC,
- Impact assessment (what asset from `docs/THREAT_MODEL.md` is at risk).

We aim to acknowledge within 3 business days, triage with a severity
assessment, and ship a fix with a `VerifyAuditChain`-clean migration path
where data repair is involved.

## What we already do

- **Threat model:** `docs/THREAT_MODEL.md` — assets, boundaries (public /
  authenticated / authorized / operator CLI), and residual risks stated
  honestly (no login throttling, no `Secure` cookie flag, pepper rotation
  invalidates all keys).
- **Vulnerability scanning:** `govulncheck ./...` runs in CI
  (`.github/workflows/ci.yml`, `govulncheck` job) and locally via
  `make vuln` (`Makefile:18-20`).
- **Dependency updates:** Dependabot is configured for Go modules and
  GitHub Actions, weekly (`.github/dependabot.yml`: `gomod` +

  `github-actions` ecosystems). `go.sum` is committed; refresh with
  `make lock` (`go mod tidy`).
- **Hygiene enforced in CI:** `gofmt` check, `go vet`, `go build`,
  `go test ./... -count=1` (`.github/workflows/ci.yml`).

## Scope notes for reporters

- Password policy floor is 12 chars with argon2id
  (`internal/auth/auth.go:26-34`); missing lockout is a *known*
  documented risk, but a bypass of the hash check itself is in scope.
- Service keys are denied by RBAC by design (`403` in
  `internal/rbac/rbac.go:61-64`, ADR 0002) — a key reaching a guarded
  route is a critical finding.
- Audit chain breaks reported by `GET /v1/audit/verify`
  (`internal/api/audit.go:32`) or `verify-audit`
  (`cmd/gatekeeper/main.go:254`) against an unmodified binary are in
  scope; verify-failure triage is in `docs/RUNBOOK.md`.
