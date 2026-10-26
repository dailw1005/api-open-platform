# Security Review: HMAC, Publication Guard, Database Foundation

## Scope

- HMAC v1 canonicalization and golden vectors.
- HMAC Servlet Filter authentication, request-body limits, error mapping and replay ordering.
- Publication activation guard.
- PostgreSQL foundation migration, composite tenant keys, RLS and active-publication triggers.

This review does not claim that the Filter is registered in a production HTTP
launcher or that the full gateway flow is complete.

## Checklist

| Area | Result | Evidence |
| --- | --- | --- |
| Hardcoded production secrets | PASS | Only deterministic test fixtures contain a fake HMAC secret; no production credential is present. |
| Secret logging | PASS | Request/result `toString()` methods redact nonce, query, body and signature material. |
| Input validation | PASS | AppKey, method, host/DNS labels, path percent encoding, query names/values, Content-Type and nonce have allowlist/format checks. |
| HTTP ambiguity | PASS | Duplicate Host, Content-Length, Content-Type and HMAC headers are rejected; missing and malformed Content-Length values fail closed. |
| Request size | PASS for 1 MiB policy | The Filter rejects declared and streamed bodies above 1 MiB before canonicalization; concurrency limits remain a gateway follow-up. |
| Injection | PASS | Database integration tests use prepared statements; migrations use static SQL and typed parameters. |
| Tenant isolation | PASS | Composite foreign keys, RLS policies and cross-tenant insert/select tests pass on PostgreSQL 18.6. |
| Publication integrity | PASS | Guard plus database trigger reject non-PROD, mismatched, revoked and reparented active publications. |
| Rollback/activation consistency | PASS for tested paths | Single ACTIVE publication, pointer mismatch and revoked-pointer protections are covered. |
| Sensitive error disclosure | PASS | The Filter returns a stable `code/message/requestId/retryable` envelope without Secret, Signature, stack trace or resolver details. |

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

### Fixed in follow-up: unauthenticated HTTP requests could bypass verifier controls

- **Severity:** High before the fix
- **Risk:** The verifier and replay guard were not connected to the public HTTP boundary, so valid and invalid request handling depended on future integration code.
- **Fix:** Added `HmacAuthenticationFilter`, raw-body caching, a 1 MiB limit, request IDs, stable error mapping and defensive Secret wiping. Signature/timestamp verification happens before nonce claim.
- **Evidence:** `HmacAuthenticationFilterTest` contains 22 tests covering success, body replay to downstream, 400/401/413/500/503 mappings, oversized streamed bodies, credential-store failure, internal-configuration redaction and exact public-path matching.

### Fixed in follow-up: ambiguous Content-Length headers were accepted

- **Severity:** High if a proxy/container normalizes conflicting lengths differently
- **Risk:** An authenticated request with duplicate `Content-Length` headers reached downstream with HTTP 200.
- **Fix:** Duplicate length headers are rejected with 400 `DUPLICATE_HEADER` before body or signature processing.
- **Evidence:** RED `c140907`; GREEN `e17b418`.

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

### Accepted: request bodies are buffered before authentication

- **Severity:** Medium until pre-auth concurrency controls are deployed
- **Residual risk:** Each in-flight signed request can retain a body of up to 1 MiB for canonicalization and downstream replay. A large unauthenticated concurrency burst can create memory pressure.
- **Required follow-up:** Enforce ingress body limits, pre-auth IP/connection rate limits, bounded server concurrency and route-specific lower limits. Revisit streaming hashing plus bounded spooling if maximum body sizes grow.

### Open: Filter is not registered by a runtime launcher

- **Severity:** High before public deployment
- **Residual risk:** Unit and Filter-chain tests prove the behavior of this component, not that a production HTTP server invokes it on every public route.
- **Required follow-up:** Add a Spring Boot/runtime integration test that boots the app, registers the Filter, resolves a credential through the real adapter and asserts the same status/error contract end to end.

## Verdict

No unresolved High finding remains in the implemented component slice. The
unregistered production launcher is explicitly High until the runtime wiring
slice lands; remaining Medium residuals are tracked in the TDD evidence report.
