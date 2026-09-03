# ADR 0001: Gapless App-Assigned Audit Sequence

Date: 2026-09-03
Status: Accepted

## Context

Gatekeeper must produce a tamper-evident audit trail that runs unchanged on
SQLite (modernc, local/dev) and Postgres (pgx, production). The schema lives
in `internal/db/migrations/001_init.sql`, where `audit_log.seq` is declared
`INTEGER PRIMARY KEY` with **no** `AUTOINCREMENT` / `SERIAL` / `GENERATED`
keyword. Sequences are assigned by the application in
`Store.AppendAudit` (`internal/store/store.go:603`); chain integrity is
checked by `Store.VerifyAuditChain` (`internal/store/store.go:669`) and
surfaced over HTTP by `handleVerifyAudit` (`internal/api/audit.go:32`,
registered as `GET /v1/audit/verify` in `internal/api/api.go:84`) and
offline by the `verify-audit` CLI (`cmd/gatekeeper/main.go:254`).

## Decision

- `AppendAudit` opens a transaction, computes
  `next = COALESCE(MAX(seq), 0) + 1`, resolves the caller's previous tip
  (`SELECT hash ... WHERE org_id = ? ORDER BY seq DESC LIMIT 1`, falling
  back to the `"genesis"` sentinel for an org with no rows), hashes with
  `AuditHash` (`store.go:597`, `sha256` over
  `prev|org|actor|action|target|detail|seq|now`), inserts the row, and
  commits. A unique-violation on `seq` under concurrency surfaces as
  `ErrConflict` so the caller can retry.
- `VerifyAuditChain` replays one org's rows in `seq` order and fails on:
  first `prev_hash != "genesis"`, any `seq` gap (`expected prev+1`),
  any recomputed-hash mismatch (tamper), any `prev_hash` that does not
  equal the previous row's `hash` (link break).
- `001_init.sql` documents the convention inline: "Audit seq is
  app-assigned inside a transaction (max+1) so the hash chain is gapless
  on both databases."

## Rationale

1. **Portability.** SQLite `AUTOINCREMENT` and Postgres `SERIAL`/`IDENTITY`
   behave differently (per-table sqlite_sequence vs. per-column sequences,
   different DDL, different placeholder rebinding). The codebase already
   abstracts multi-DB support via `db.Rebind` (`internal/db/db.go:62`,
   `?` → `$n`); app-assigned `MAX+1`-in-tx keeps the migration file
   identical for both engines.
2. **Gap detection = tamper evidence.** A DB sequence guarantees
   uniqueness, not contiguity: rolled-back transactions and sequence
   caching consume values and leave gaps. With a native sequence, a
   deleted audit row is indistinguishable from a rolled-back insert —
   both look like a missing number. With app-assigned dense numbering,
   `VerifyAuditChain` treats *any* missing `seq` as a break
   (`store.go:703`), so deletion is detectable, not silent.
3. **Per-org genesis.** `prev_hash = "genesis"` anchors each org's first
   entry without a shared bootstrap row, keeping orgs independent while
   `seq` stays global and dense.

## Alternatives considered (rejected)

- **Native `AUTOINCREMENT`/`SERIAL` + hash-only verification (no gap
  check).** Rejected: gaps become normal, so row deletion stops being
  detectable — the chain degrades from tamper-evident to
  tamper-suggestive.
- **Per-org sequence table / `SELECT ... FOR UPDATE` counter row.**
  Rejected: extra DDL and lock-coupling for no additional evidentiary
  value; `MAX(seq)` in the write transaction is sufficient at this
  workload.
- **UUID primary key + `created_at` ordering.** Rejected: wall-clock
  ties and skew make ordering ambiguous; verification would need a
  tiebreak rule that is itself attackable.

## Consequences

- Writers serialize on the audit table's write transaction; concurrent
  appends can hit `ErrConflict` and must retry (callers in
  `internal/api/api.go:132` currently log-and-ignore audit errors, so a
  conflict there means a dropped entry — see Residual risks in
  `docs/THREAT_MODEL.md`).
- `seq` is global across orgs while `prev_hash` chains are per-org; the
  `idx_audit_org_seq` index (`001_init.sql:123`) keeps per-org replay
  cheap.
