# Security Review: HMAC, Publication Guard, Database Foundation

## Scope

- HMAC v1 canonicalization and golden vectors.
- HMAC Servlet Filter authentication, request-body limits, error mapping and replay ordering.
- Spring Boot runtime registration, JDBC credential resolution and concrete AWS KMS decryptor.
- Exact-route application/API authorization and pre-authentication rate limiting.
- Publication activation guard.
- PostgreSQL foundation, credential and API authorization lookup migrations, composite tenant keys, RLS and active-publication triggers.

This review does not claim that real staging AWS KMS/key-policy validation,
trusted proxy IP extraction, post-auth app/API quotas or upstream routing is complete.

## Checklist

| Area | Result | Evidence |
| --- | --- | --- |
| Hardcoded production secrets | PASS | Only deterministic test fixtures contain a fake HMAC secret; no production credential is present. |
| Secret logging | PASS | Request/result `toString()` methods redact nonce, query, body and signature material. |
| Input validation | PASS | AppKey, method, host/DNS labels, path percent encoding, query names/values, Content-Type and nonce have allowlist/format checks. |
| HTTP ambiguity | PASS | Duplicate Host, Content-Length, Content-Type and HMAC headers are rejected; missing and malformed Content-Length values fail closed. |
| Request size | PASS for 1 MiB policy | The Filter rejects declared and streamed bodies above 1 MiB before canonicalization; concurrency limits remain a gateway follow-up. |
| Runtime registration | PASS | A Spring Boot integration test starts embedded Tomcat, posts a signed HTTP request through the registered Filter, consumes the Nonce and rejects replay. |
| Credential lookup privilege | PASS | `auth_resolve_active_credential` is `SECURITY DEFINER`, has a fixed `search_path`, revokes `PUBLIC`, and is tested through the non-superuser `app_runtime` role with explicit `EXECUTE`. |
| Credential lifecycle | PASS | Active and unexpired rotating credentials resolve; suspended tenant/app, revoked and expired credentials return no row. |
| KMS encryption context | PASS | AWS KMS decrypt requests bind `tenantId`, `appId`, `credentialId` and `appKey`; 429/5xx and transport errors are retryable, deterministic KMS failures are not. |
| Database role verification | PASS | Startup rejects superuser/BYPASSRLS roles, requires both authentication function grants, and rejects direct `app_credential` DML access. The runtime E2E test uses a restricted login role. |
| API authorization | PASS | Exact active method/path, PROD publication, tenant visibility and ACTIVE app grant are required after signature/Nonce verification; no-grant returns 403 and unpublished/foreign-private routes return 404. |
| Pre-auth rate limit | PASS | Redis Lua applies atomic fixed-window per-IP limiting before Header/body processing; denial is 429 with standard Headers and Redis errors fail closed as 503. |
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
- **Evidence:** `HmacAuthenticationFilterTest` covers success, body replay, rate limiting, authorization, 400/401/403/404/413/429/500/503 mappings and Secret redaction.

### Fixed in follow-up: ambiguous Content-Length headers were accepted

- **Severity:** High if a proxy/container normalizes conflicting lengths differently
- **Risk:** An authenticated request with duplicate `Content-Length` headers reached downstream with HTTP 200.
- **Fix:** Duplicate length headers are rejected with 400 `DUPLICATE_HEADER` before body or signature processing.
- **Evidence:** RED `c140907`; GREEN `e17b418`.

### Fixed: Filter was not registered by a runtime launcher

- **Severity:** High before the fix
- **Risk:** Component tests did not prove that Tomcat invoked the Filter or that a credential could be resolved from PostgreSQL and decrypted through the runtime boundary.
- **Fix:** Added `platform-app`, Spring Boot Filter registration, Jedis wiring, a JDBC resolver, typed failure mapping and the executable Spring Boot JAR.
- **Evidence:** `RuntimeHmacIntegrationTest` boots embedded Tomcat against PostgreSQL 18.6 and Redis, verifies a signed request reaches the downstream handler, and verifies replay and suspended-app rejection. RED `3e36dce`; GREEN `eaa0f08`.

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

### Fixed: credential decryption and database role were not production adapters

- **Severity:** High before the fix
- **Risk:** The runtime only had a KMS port fake and did not reject an overprivileged database login.
- **Fix:** Added `AwsKmsCredentialSecretDecryptor` with exact encryption context, 3-second timeout and typed retry classification. Added startup role verification for both lookup functions, superuser, BYPASSRLS and direct credential-table access. The HTTP E2E test now uses a restricted PostgreSQL login role.
- **Evidence:** `AwsKmsCredentialSecretDecryptorTest`, `GatewayDatabaseRoleVerifierTest`, `RuntimeHmacIntegrationTest`.

### Fixed: signed callers were not checked against app/API grants

- **Severity:** High before the fix
- **Risk:** A valid app credential could reach any `/open/v1/**` route without an ACTIVE application grant.
- **Fix:** Added `auth_authorize_public_api` and `JdbcApiAuthorizationGate`; authorization runs only after signature verification and Nonce claim.
- **Evidence:** `ApiAuthorizationLookupTest`, `JdbcApiAuthorizationGateTest`, `HmacAuthenticationFilterTest`, `RuntimeHmacIntegrationTest`.

### Fixed: requests reached expensive authentication without a coarse abuse limit

- **Severity:** High before the fix
- **Risk:** Arbitrary clients could force HMAC parsing, database lookup and KMS decryption without a pre-auth budget.
- **Fix:** Added a Redis Lua fixed-window per-IP limiter before Header/body processing, standard rate-limit Headers, 429 and fail-closed 503.
- **Evidence:** `RedisPreAuthRateLimiterTest`, `HmacAuthenticationFilterTest`, `RuntimeHmacIntegrationTest`.

### Accepted: every authenticated request performs database and KMS work

- **Severity:** Medium until capacity testing
- **Residual risk:** The current resolver has no Secret cache. Revocation is immediate, but request latency and dependency load include PostgreSQL lookup plus KMS decryption for every valid request.
- **Required follow-up:** Establish QPS/latency targets, add bounded load tests, then introduce a short-TTL cache only with app/credential epoch validation and an explicit maximum staleness window.

### Open deployment prerequisite: real staging KMS and role validation

- **Severity:** High before production startup
- **Residual risk:** Embedded tests prove request shape and classification, but not the real AWS account, key policy, credential provider, network path, latency or database grants.
- **Required follow-up:** Execute `docs/operations/staging-security-validation.md` against staging AWS KMS, PostgreSQL login role, Redis TLS and the deployed container identity.

### Accepted: pre-auth limiting uses `remoteAddr`

- **Severity:** High if deployed behind an unconfigured reverse proxy
- **Residual risk:** Without trusted proxy configuration, all clients can appear as the proxy address, causing shared exhaustion; blindly trusting client-supplied `X-Forwarded-For` permits bypass.
- **Required follow-up:** Terminate untrusted traffic at a trusted ingress and configure an explicit proxy allowlist and IP extraction rule, or enforce equivalent ingress and connection limits.

### Accepted: fixed window and per-IP-only rate limiting

- **Severity:** Medium
- **Residual risk:** A boundary burst can approach twice the configured rate, NAT clients share a bucket, and authenticated per-app/API quotas are not yet enforced.
- **Required follow-up:** Add per-app/API post-auth token-bucket or sliding-window limits, quotas and load tests; retain the pre-auth limit as one defense layer.

### Accepted: authorization uses exact route matching

- **Severity:** Medium
- **Residual risk:** APIs with path parameters are not matched by `auth_authorize_public_api`; treating templates as literals would make them unreachable or, if changed carelessly, risks ambiguous authorization.
- **Required follow-up:** Add a reviewed route-template compiler with precedence and ambiguity tests before enabling parameterized public paths.

## Verdict

No unresolved High finding remains in the implemented and locally tested
component boundaries. Real staging dependencies and trusted client-IP
configuration remain explicit High deployment prerequisites; remaining Medium
residuals are tracked in the TDD evidence report.
