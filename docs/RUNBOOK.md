# Runbook — Gatekeeper

All commands run against `GATEKEEPER_DATABASE_URL`
(default `sqlite://./gatekeeper.db`, `internal/config/config.go:35`).
CLI surface is exactly
`provision-org | create-user | serve | migrate | verify-audit`
(`cmd/gatekeeper/main.go:51-69`). There is **no rotate endpoint** —
verified: no match for `rotat` anywhere in `internal/api/`, and the
route table in `internal/api/api.go:50-91` lists only
`/v1/api-keys/{id}/revoke` for key lifecycle.

## Provision an org

```sh
go run ./cmd/gatekeeper provision-org \
  --name "Acme" --email admin@acme.example --password '<≥12 chars>'
# → {"org_id":"…","user_id":"…","api_key":"gk_live_…"}  (main.go:71-127)
```

Creates org + `admin` role with `"*"` (`SetRolePermissions`,
`store.go:311`) + admin user + one `provision` API key, and writes
`orgs.provision` to the audit log. **Save the `api_key` and `org_id`
now — the raw key is never shown again** (`keys.go:51-54`).

## Create a user

```sh
go run ./cmd/gatekeeper create-user \
  --org <org_id> --email jdoe@acme.example \
  --password '<≥12 chars>' --name "J Doe" --roles admin
# --roles accepts role names or ids, comma-separated (main.go:179-191)
```

Or via API: `POST /v1/users` (`guard("users:write")`,
`api.go:63`) with `{"email","name","password","role_ids"}`.

## Rotate pepper / keys (re-issue procedure)

Pepper (`GATEKEEPER_PEPPER`, `config.go:37`) is mixed into every key
hash (`HashAPIKey`, `auth.go:119`). Changing it invalidates **all**
existing API keys at once — there is no dual-pepper or migration path.
Procedure:

1. During a window: issue replacement keys first —
   `POST /v1/api-keys` (`keys.go:13`, needs `keys:write`) for each
   consumer; distribute the one-time `api_key` values.
2. Revoke the old keys — `POST /v1/api-keys/{id}/revoke`
   (`keys.go:83`, needs `keys:write`) — or let `expires_in_hours` lapse.
3. Set the new `GATEKEEPER_PEPPER`, restart (`serve`, `main.go:200`),
   confirm new-key auth works; old hashes will simply stop matching
   (`authenticateAPIKey`, `auth.go:264` → `auth: unknown api key`).
4. Confirm `GET /v1/api-keys` shows expected `revoked` flags.

Session tokens are **not** peppered (`HashSessionToken`, `auth.go:135`)
and survive pepper rotation; to force re-login, delete rows from
`sessions` or suspend users (`PATCH /v1/users/{id}`,
`handlePatchUser`, `users.go:211`).

## Close a review campaign

```sh
# list → decide remaining items → close
curl -b cookies "$BASE/v1/reviews/campaigns"
curl -b cookies "$BASE/v1/reviews/campaigns/{id}/items"
curl -X POST -b cookies -d '{"decision":"certified"}' \
  "$BASE/v1/reviews/items/{itemID}/decide"   # or "revoked" (revoke-first, ADR 0003)
curl -X POST -b cookies "$BASE/v1/reviews/campaigns/{id}/close"
```

`CloseCampaign` (`store.go:824`) refuses with `409` while any item is
`pending`; all calls need `reviews:read` / `reviews:write`
(`api.go:77-81`).

## Verify the audit chain

```sh
go run ./cmd/gatekeeper verify-audit --org <org_id>
# → {"ok":true} or {"ok":false,"error":"…"} (exit 1, main.go:254-280)
```

and/or over HTTP (needs `audit:read`):

```sh
curl -b cookies "$BASE/v1/audit/verify"        # {"ok":true} or 409 with reason
curl -b cookies "$BASE/v1/audit?since_seq=0&limit=50"
```

## SQLite backup

Stop-the-world copy is simplest and safe for SQLite:

```sh
sqlite3 gatekeeper.db ".backup 'gatekeeper-$(date +%F).db'"
# file layout: sqlite://PATH → file:PATH (internal/db/db.go:31)
```

For Postgres use `pg_dump`. Protect backups like secrets: they contain
password hashes, session/key hashes, and full PII.

## On verify failure

1. Capture the error — it names the culprit:
   - `audit chain gap for org …: expected seq N, got M` → rows deleted
     (or a dropped append, see residual risk 3 in THREAT_MODEL).
   - `audit chain tamper at seq N: hash mismatch` → row N edited.
   - `audit chain broken at seq N: prev_hash …` → splice/reorder.
   - `first prev_hash = … want "genesis"` → head deleted.
2. Pull the neighbourhood: `GET /v1/audit?since_seq=<N-2>&limit=10` and
   compare against a known-good backup.
3. Freeze writes if tamper is suspected (revoke keys, suspend users,
   stop `serve`), preserve the DB file read-only, investigate operator
   access (CLI `verify-audit` bypasses HTTP auth) before repairing.
4. Do **not** "fix" the chain by rewriting hashes — re-provision from a
   verified backup and re-apply legitimate operations so the new chain
   is genuinely gapless.
