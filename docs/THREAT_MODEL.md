# Threat Model — Gatekeeper (workforce IAM)

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Password verifiers | `users.password_hash` (`001_init.sql:21`) | argon2id `time=3, memory=64MiB, threads=4, keylen=32`, 16-byte salt, 12-char minimum (`internal/auth/auth.go:26-34`, `HashPassword` at `:52`) |
| Session tokens | `sessions.token_hash` + `gk_session` cookie | Stored as `sha256hex(raw)` (`NewSessionToken`, `auth.go:125`); cookie is `HttpOnly`, `SameSite=Lax` (`internal/api/users.go:56-59`, `internal/api/oidc.go:111-114`); TTL default 12h (`sessionTTL`, `users.go:14`; `GATEKEEPER_SESSION_HOURS`) |
| API keys | `api_keys.key_hash`; raw shown once at creation | Stored as `sha256hex(pepper + "::" + raw)` (`HashAPIKey`, `auth.go:119`); only the last-8-char `prefix` is returned for display (`handleListAPIKeys`, `internal/api/keys.go:62`) |
| Audit integrity | `audit_log(seq, prev_hash, hash)` | Hash chain (`AuditHash`, `store.go:597`; `AppendAudit`, `store.go:603`) + `VerifyAuditChain` (`store.go:669`), endpoint `GET /v1/audit/verify` (`internal/api/audit.go:32`), CLI `verify-audit` (`cmd/gatekeeper/main.go:254`) |
| OIDC trust | `Config.OIDCIssuer/ClientID/Secret/RedirectURL` (`internal/config/config.go:16-20`) | Live `go-oidc` verifier bound to issuer + `ClientID` audience (`NewOIDCVerifier`, `auth.go:158`); `501 oidc not configured` unless all four set (`OIDCEnabled`, `config.go:50`; `internal/api/oidc.go:21-40`) |

## Trust boundaries

1. **Public:** `GET /healthz`, `POST /v1/login`, `GET /v1/oidc/login|callback`
   (`internal/api/api.go:50-56`) — reachable without credentials.
2. **Authenticated:** everything under `r.Use(d.Auth.Middleware)`
   (`api.go:58-85`, SCIM at `:87-92`) — requires valid session cookie or
   `X-API-Key` (`auth.go:325`).
3. **Authorized:** routes additionally wrapped in `d.guard(perm, ...)`
   (`api.go:38` → `rbac.Require`, `rbac.go:54`) — requires a *user
   session* with the permission via `Store.UserPermissions`.
4. **Operator CLI** (`cmd/gatekeeper/main.go:49-69`): `provision-org`,
   `create-user`, `migrate`, `verify-audit` bypass HTTP auth and need
   direct DB/env access — treat the host running them as trusted.

## Threats & mitigations

- **T1 Password spraying / guessing.** Costly argon2id + 12-char floor
  raise per-guess cost; login returns generic `invalid credentials`
  (`users.go:36-43`) so enumeration via timing/message is minimized.
  **Stated honestly: there is no lockout, no throttling, no rate
  limiting** — no such code exists in `internal/` (verified by search).
  Mitigate by fronting with a rate-limiting proxy and alerting on
  `users.login` audit volume.
- **T2 Session theft (XSS / transport).** `HttpOnly` blocks JS theft;
  only hashes are stored so DB read ≠ session hijack; TTL + logout
  deletion (`handleLogout`, `users.go:63`; `DeleteSession`,
  `store.go:557`) bound the window; suspended users' sessions stop
  working (`authenticateSession`, `auth.go:282`). **Honest gaps:** no
  `Secure` flag is set on the cookie and login/OIDC responses also echo
  the raw token in the JSON body (`users.go:60`, `oidc.go:115`) — deploy
  HTTPS-only and prefer the cookie over the body token.
- **T3 API-key leakage (logs, backups, repo).** Peppered hash means a DB
  dump alone does not yield usable keys; list endpoints expose only
  `prefix`/`id`, never hashes (`keys.go:73-80`); raw key is returned
  exactly once at creation (`keys.go:51-54`, CLI `main.go:126`).
  Revocation (`RevokeAPIKey`, `store.go:517`,
  `POST /v1/api-keys/{id}/revoke`) and expiry (`ExpiresInHours`,
  `keys.go:39`) bound exposure.
- **T4 Audit tampering (edit/delete/backdate).** Any modification breaks
  the recomputed hash; any deletion breaks the dense-`seq` check or the
  `prev_hash` link (`VerifyAuditChain`, `store.go:696-713`); genesis
  anchor (`prev_hash == "genesis"`) prevents chain splicing. Verify via
  `GET /v1/audit/verify` or the CLI.
- **T5 OIDC misconfiguration / token forgery.** `NewOIDCVerifier` pins
  issuer discovery + audience; handlers return `501` when unset rather
  than degrading to insecure login; callback rejects missing
  email/subject (`oidc.go:53`); OIDC-created users get an unusable random
  argon2id password (`oidc.go:78`) so IdP users cannot password-login.
- **T6 Privilege escalation via cross-org IDs.** Verified by reading
  `internal/store/store.go`: `GetUser`, `GetUserByEmail`, `ListUsers`,
  `SetUserStatus`, `RenameUser`, `GetRole`, `ListRoles`, `ListAPIKeys`,
  `RevokeAPIKey`, `GetCampaign`, `ListCampaigns`, `CloseCampaign`,
  `ListAudit` all filter by `org_id`; `SetUserRoles` explicitly rejects
  user/role org mismatch (`store.go:391-405`). Item lookup is org-scoped
  one layer up (`findItem` scans only the caller's org campaigns,
  `reviews.go:100`). Known narrow exceptions, not bypasses:
  `GetAPIKeyByHash`/`GetSessionByHash` look up by hash (required — the
  raw secret is the lookup key) and the org is then *taken from* the
  record; `UserRoles`/`UserPermissions` take only a `userID` and rely on
  callers passing IDs already resolved within-org.
- **T7 Webhooks: not applicable.** Verified by search — no webhook
  sender, receiver, or secret exists in the codebase; no SSRF-via-webhook
  or replay surface to model.

## Residual risks (accepted, not fixed)

1. No login rate limiting / lockout (T1) — needs edge enforcement.
2. Cookie lacks `Secure`; raw session token also in response bodies —
   needs HTTPS + careful log redaction.
3. Audit append conflicts retry with `ErrConflict`, but the HTTP helper
   `Deps.audit` (`api.go:132`) ignores errors — a conflict there silently
   drops an entry; verify cadence (runbook) is the backstop.
4. `GET /v1/me` reports `"permissions": ["*"]` for key identities
   (`users.go:84`) — display-only today, but any future consumer that
   trusts it reintroduces ambient authority (see ADR 0002).
5. Default pepper `dev-pepper-change-me` (`config.go:37-46`) — safe only
   for dev; rotating it invalidates all existing keys (no dual-pepper
   support).
