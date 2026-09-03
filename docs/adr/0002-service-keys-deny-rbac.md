# ADR 0002: Service Keys Are Denied by RBAC (`Require` → 403)

Date: 2026-09-03
Status: Accepted

## Context

Gatekeeper has two credential types, resolved in
`Authenticator.Middleware` (`internal/auth/auth.go:325`): the
`gk_session` cookie (user session, `Identity{Kind: "session"}` with a
`UserID`) and the `X-API-Key` header (`APIKeyHeader`, `auth.go:40`),
which yields an org-scoped service identity
`Identity{OrgID, UserID: "", Kind: "api_key"}` (`auth.go:336`).
RBAC-protected routes are wrapped by `Deps.guard`
(`internal/api/api.go:38`), which delegates to `rbac.Require`
(`internal/rbac/rbac.go:54`).

## Decision

`rbac.Require` fails closed on key identities: any `Identity` with an
empty `UserID` gets `403 "service keys cannot satisfy RBAC; use a user
session"` (`rbac.go:61-64`) without consulting `Store.UserPermissions`.
Unauthenticated requests (no identity at all) get `401`; key requests
are authenticated but unauthorized for every guarded route. Automation
that needs RBAC-protected endpoints (`/v1/users`, `/v1/roles`,
`/v1/api-keys`, `/v1/reviews/...`, `/v1/audit`, `/scim/v2/Users` — all
registrations in `internal/api/api.go:63-91`) must therefore log in as a
user (`POST /v1/login`, `internal/api/users.go:21`) or complete OIDC
(`GET /v1/oidc/login`, `GET /v1/oidc/callback`) and present the resulting
session token.

## Rationale

1. **Keys carry no roles.** The `api_keys` table
   (`001_init.sql:49-58`) has `id, org_id, name, key_hash, prefix,
   expires_at, revoked, created_at` — no user binding, no scope column.
   There is nothing for `UserPermissions` (`store.go:444`) to resolve, so
   any grant the middleware invented would be ambient authority.
2. **Schema is frozen.** The package comment on `internal/rbac/rbac.go:1`
   records the posture explicitly: the schema gains no user/scope column
   for keys, so there is no safe least-privilege attachment point.
3. **Fail closed beats fail convenient.** Permitting keys past `Require`
   with an assumed-empty permission set would break open the moment
   someone "helpfully" defaults them; denying categorically keeps the
   invariant obvious and greppable.

## Alternatives considered (deferred, not rejected outright)

- **Key→role mapping table** (`api_key_roles` + `SetKeyRoles`, mirroring
  `SetUserRoles` at `store.go:368`). Deferred: it is the right long-term
  fix for service automation, but it needs new DDL, issuance UX (which
  roles at `POST /v1/api-keys` time?), `Require` semantics for the
  dual-identity case, and audit coverage — a larger change than the
  frozen-schema posture allows right now. When built, keys should get
  explicit, minimal grants, never `"*"` (note that `handleMe` today
  reports `"permissions": ["*"]` for key identities at
  `internal/api/users.go:84` — display-only, not enforced — which must
  not become enforcement).
- **Per-endpoint key allowlist.** Rejected: scatters policy across
  handlers and rots; the single choke point in `Require` is auditable.

## Consequences

- Service-to-service callers must manage session lifecycles (TTL default
  12h, `sessionTTL` in `internal/api/users.go:14`); key-only automation
  is limited to whatever unguarded surface exists (today: only
  `/healthz`, OIDC/login).
- `actorOf` (`api.go:114`) attributes key-performed audit writes as
  `"api_key"`; keys can still authenticate (pass `Middleware`) and reach
  non-`guard` handlers, so audit attribution stays coarse for any future
  unguarded writes.
