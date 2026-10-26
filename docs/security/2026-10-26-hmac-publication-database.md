# Security Review: HMAC, Publication Guard, Database Foundation

## Scope

- HMAC v1 canonicalization and golden vectors.
- Publication activation guard.
- PostgreSQL foundation migration, composite tenant keys, RLS and active-publication triggers.

This review does not claim that the full gateway authentication flow is complete.

## Checklist

| Area | Result | Evidence |
| --- | --- | --- |
| Hardcoded production secrets | PASS | Only deterministic test fixtures contain a fake HMAC secret; no production credential is present. |
| Secret logging | PASS | Request/result `toString()` methods redact nonce, query, body and signature material. |
| Input validation | PASS | AppKey, method, host/DNS labels, path percent encoding, query names/values, Content-Type and nonce have allowlist/format checks. |
| Injection | PASS | Database integration tests use prepared statements; migrations use static SQL and typed parameters. |
| Tenant isolation | PASS | Composite foreign keys, RLS policies and cross-tenant insert/select tests pass on PostgreSQL 18.6. |
| Publication integrity | PASS | Guard plus database trigger reject non-PROD, mismatched, revoked and reparented active publications. |
| Rollback/activation consistency | PASS for tested paths | Single ACTIVE publication, pointer mismatch and revoked-pointer protections are covered. |
| Sensitive error disclosure | PASS | Stable error codes are separated from internal exception details at the domain boundary. |

## Findings

### Fixed: active publication could be revoked while still active

- **Severity:** High
- **Scenario:** An `ACTIVE` publication referenced by `api_definition.active_prod_publication_id` was changed directly to `REVOKED`, leaving the active route pointing at a revoked artifact.
- **Fix:** Added an immediate publication-side trigger that rejects revocation or reparenting while referenced by an active pointer, plus a deferred constraint trigger that requires the pointer to reference an `ACTIVE` publication at commit.
- **Evidence:** `DatabaseFoundationTest#cannotRevokePublicationWhileActivePointerReferencesIt` and `DatabaseFoundationTest#cannotCommitSupersededPublicationWhileStillActive`.

### Fixed in follow-up: HMAC verifier and replay protection

- **Severity:** High before the fix
- **Risk:** The canonicalizer generated signatures, but no verifier enforced timestamp skew, constant-time comparison or nonce replay protection.
- **Fix:** Added `HmacVerifier`, `HmacRequestAuthenticator`, hashed nonce keys, a 660-second TTL and a Redis `SET NX PX` store. Embedded Redis tests prove single-winner concurrency.
- **Evidence:** `HmacVerifierTest`, `HmacRequestAuthenticatorTest`, `NonceReplayGuardTest`, `JedisNonceReplayStoreTest`.
- **Residual:** The chain is not yet wired to the HTTP filter; Redis must run with `noeviction`, auth and TLS in production.

### Accepted: RLS trusts `app.tenant_id`

- **Severity:** Medium
- **Residual risk:** A compromised runtime connection could set its own custom GUC. RLS is defense in depth, not a replacement for authenticated tenant-context propagation.
- **Required follow-up:** A single trusted tenant-context middleware must set/reset `app.tenant_id` around each transaction; all runtime SQL must remain parameterized.

### Accepted: usage and audit tables are not in V1

- **Severity:** Medium for production billing/audit readiness
- **Residual risk:** Usage, request logs, audit logs and retention jobs are not yet persisted.
- **Required follow-up:** Add a later migration with partition/retention design and immutable/append-only access rules.

### Accepted: nonce availability shares Redis with cache/rate-limit state

- **Severity:** Medium
- **Residual risk:** Eviction, TLS/ACL misconfiguration or a shared noisy Redis can weaken replay protection or take the auth path down.
- **Required follow-up:** Use an isolated Redis logical database/instance with `noeviction`, authentication, TLS, bounded connection/command timeouts and fail-closed alerts.

## Verdict

No unresolved High finding remains in this slice. Medium residuals are explicit gateway/DB follow-ups and are covered by the TDD evidence report.
