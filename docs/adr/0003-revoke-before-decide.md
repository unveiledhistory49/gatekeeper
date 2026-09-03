# ADR 0003: Revoke-Before-Decide in Access Review Decisions

Date: 2026-09-03
Status: Accepted

## Context

Access recertification flows through `handleDecideItem`
(`internal/api/reviews.go:119`, `POST /v1/reviews/items/{itemID}/decide`
in `internal/api/api.go:80`). A `"revoked"` decision must do two things:
remove the role grant (`Store.SetUserRoles`, `store.go:368`) and record
the decision (`Store.DecideReviewItem`, `store.go:794`). `DecideReviewItem`
is one-way: it only transitions `pending` → `certified`/`revoked` and
rejects re-decision (`store.go:806-820`, `409 Conflict` via the handler
at `reviews.go:171`).

## Decision

For `decision == "revoked"`, the handler removes the role **first**
(`reviews.go:148-165`: load `UserRoles`, filter out the reviewed role,
`SetUserRoles`, audit `reviews.revoke_role`) and only then calls
`DecideReviewItem` and audits `reviews.decide` (`reviews.go:166-174`).
Enforcement precedes bookkeeping.

## Rationale

The reverse order wedges the item. If the decision were recorded first
and the subsequent `SetUserRoles` failed (DB error, org-mismatch,
crash), the item would sit in a **decided-but-not-enforced** state: the
user keeps access they were explicitly denied, and `DecideReviewItem`'s
pending-guard makes the failure un-retryable through the API — a human
would have to repair `user_roles` out of band while the audit log claims
`reviews.decide=revoked`. Revoke-first inverts the failure modes into
safe ones:

- Role removal fails → item stays `pending`, reviewer retries; no audit
  claim has been made yet.
- `DecideReviewItem` fails after removal → access is already revoked
  (the security-relevant effect holds); the item stays `pending` and a
  retry re-runs removal idempotently (re-setting the already-filtered
  role list is a no-op) before recording.

## Alternatives considered (rejected)

- **Decide-then-revoke.** Rejected: creates the un-retryable wedge above.
- **Single DB transaction spanning both.** Rejected: the two operations
  live in different layers (role-membership write vs. review-state
  machine) and the handler deliberately sequences two store calls so each
  keeps its own error semantics (`cannot revoke role` → 500 vs.
  already-decided → 409); a cross-concern transaction would couple them
  without removing the crash-between-commit-and-response window anyway.

## Consequences

- A retry after a successful removal but failed decision emits a second
  `reviews.revoke_role` audit entry; readers must tolerate duplicate
  revoke audit lines for one item.
- `"certified"` decisions skip the removal branch entirely and go
  straight to `DecideReviewItem` — no ordering concern.
