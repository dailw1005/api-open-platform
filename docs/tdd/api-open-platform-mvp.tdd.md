# API Open Platform MVP TDD Evidence

## Source

- Approved plan: `plans/api-open-platform-mvp.md`
- Contract map: `docs/tdd/api-open-platform-mvp.contract-map.md`
- Gate 0 contract: `docs/contracts/gate-0.md`
- Staging security runbook: `docs/operations/staging-security-validation.md`
- Single API proxy design: `docs/architecture/single-api-proxy.md`

## Gate 0 Contract Cycle

- **Command:** `mvn test`
- **Initial result:** RED, 3 failing contract checks.
- **Initial failures:**
  - DSL `$ref` value matched both reference and generic object variants under `oneOf`.
  - Public gateway signature headers were declared at path level and not included by the initial operation-level test.
  - Component error responses were not resolved by the parser model in the initial envelope test.
- **Minimal corrections:**
  - Changed recursive DSL value composition from `oneOf` to `anyOf`.
  - Combined path-level and operation-level parameters in the contract test.
  - Validated error-response `$ref` chains against the raw YAML contract.
- **Final result:** GREEN, `Tests run: 12, Failures: 0, Errors: 0, Skipped: 0`.

## First Production RED

- **Test:** `orchestration-engine/src/test/java/com/apiproject/orchestration/FlowValidatorTest.java`
- **Command:** `mvn -pl orchestration-engine test`
- **Result:** RED at test compilation.
- **Failure:** Missing `FlowValidator`, `FlowValidationResult`, `FlowValidationIssue`, `ApiMetadataResolver`, `ApiMetadata`, and `ApiKind`.
- **Why valid RED:** The missing API is the exact production boundary defined by the contract; fixtures were already validated by the Gate 0 schema test.

## User Journeys

1. A platform administrator can publish a contract-valid API and review a tenant orchestration.
2. An application developer can create an app and obtain a one-time credential secret.
3. An external application can sign a request according to HMAC v1.
4. A viewer can read visible published APIs, app metadata, usage, and sanitized logs without writing.
5. An administrator can revoke or suspend resources and protected requests fail closed.

## Task Evidence

| Task | Test target | RED | GREEN | Guarantee |
| --- | --- | --- | --- | --- |
| Gate 0 OpenAPI | `OpenApiContractTest` | Initial contract checks failed as recorded above | 7/7 passed | Required operations, auth extensions, CSRF, HMAC headers, and errors are present |
| Gate 0 DSL | `DslSchemaContractTest` | Valid fixture rejected by schema composition | 5/5 passed | Structural DSL contract accepts valid input and rejects script/URL/retry violations |
| Flow validation | `FlowValidatorTest` | Compile-time RED confirmed | 21/21 passed | Duplicate IDs, references, nested flows, safe retries, timeout, overlapping writes, and DSL-only declaration traversal are checked |

## Coverage And Known Gaps

- Gate 0 contract tests do not implement provider behavior.
- Flow validator GREEN evidence: `mvn -pl orchestration-engine verify`.
- Flow validator coverage: line 92.98% (212/228), branch 82.81% (106/128).
- JaCoCo enforces 80% line and 80% branch coverage for `orchestration-engine`.
- Runtime DSL byte/node/depth budget enforcement remains a later execution-layer task.
- Git checkpoints preserve each RED/GREEN stage on `master`.

## Second RED/GREEN Cycle

- **Behavior added:** overlapping parallel variable paths such as `vars/shared` and `vars/shared/child` must conflict.
- **RED command:** `mvn -pl orchestration-engine test`
- **RED result:** 12 tests, 1 failure; the validator reported only stale output references and did not emit `DSL_PARALLEL_VAR_CONFLICT`.
- **Minimal fix:** compare branch writes for equality and ancestor/descendant path overlap.
- **GREEN result:** 19 tests, 0 failures at that checkpoint.

## Third RED/GREEN Cycle

- **Behavior added:** variable declarations and parallel writes are collected only from DSL control nodes.
- **RED command:** `mvn -pl orchestration-engine test`
- **RED result:** 21 tests, 2 failures.
  - `inputSchema.defaults` incorrectly created a runtime variable declaration.
  - A business payload field named `assign` was incorrectly treated as a parallel variable write.
- **Minimal fix:** replaced generic recursive object scanning with explicit traversal of `defaults`, `assign`, `outputMapping`, `steps`, `then`, `else`, `branches`, `try`, and `catch`.
- **GREEN command:** `mvn -pl orchestration-engine verify`
- **GREEN result:** 21 tests, 0 failures; 80% line and branch coverage gates pass.
- **Final full command:** `mvn verify`
- **Final full result:** BUILD SUCCESS; 33 tests total across contract and engine modules.

## HMAC v1 Slice

- **RED:** `mvn -pl gateway-runtime test` failed compilation because `HmacCanonicalizer`, request/result records and typed exception did not exist.
- **Golden vectors:** GET with empty body, sorted query, lowercase host/default-port normalization; POST with UTF-8 JSON, Content-Type parameters and encoded reserved characters.
- **Security RED:** 5 tests exposed short-secret acceptance, method whitespace, invalid DNS label and leaky `toString()` methods.
- **GREEN:** `mvn -pl gateway-runtime verify`
- **Tests:** 47 passed.
- **Coverage:** line 96.99% (258/266), branch 83.64% (179/214).
- **Security behavior:** AppKey/nonce allowlists, 256-bit minimum Secret, strict percent encoding, raw `+` rejection, dot/slash rejection, Unicode path encoding, DNS label validation and redacted diagnostics.

## Publication Guard Slice

- **Contract-first change:** publication states are `PREPARED`, `ACTIVE`, `SUPERSEDED`, `REVOKED`.
- **RED:** `mvn -pl platform-control test` failed because guard types did not exist.
- **GREEN:** `mvn -pl platform-control verify`
- **Tests:** 10 passed.
- **Coverage:** line 100% (49/49), branch 95.00% (19/20).
- **Security behavior:** rejects SANDBOX, API mismatch, tenant mismatch, visibility mismatch, revoked publication and invalid operation/state combinations.

## PostgreSQL Foundation Slice

- **RED:** `mvn -pl platform-persistence test` migrated zero files and failed all foundation table/RLS/constraint tests.
- **Runtime:** native PostgreSQL 18.6 through `embedded-postgres`; no Docker dependency.
- **Migration:** `platform-persistence/src/main/resources/db/migration/V1__foundation.sql`.
- **GREEN:** `mvn -pl platform-persistence test`
- **Tests:** 9 passed.
- **Coverage:** Flyway migration is exercised by real PostgreSQL integration tests rather than Java line coverage.
- **Security RED:** active publication could be revoked while referenced by the active pointer.
- **Security fix:** immediate publication-side trigger rejects revocation/reparenting while active; deferred constraint trigger verifies the active pointer still references `ACTIVE` at commit.

## Security Review

- **Review artifact:** `docs/security/2026-10-26-hmac-publication-database.md`
- **High findings:** none in the implemented and tested component boundaries.
- **Deployment prerequisites:** a concrete KMS decryptor and least-privilege production database grants are still required.
- **Residual Medium items:**
  - Every valid request currently performs a PostgreSQL lookup and KMS-port decryption; cache/capacity behavior is not load-tested.
  - Application/API grant authorization, rate limiting, routing and proxy/orchestration dispatch are not implemented.
  - RLS depends on trusted `app.tenant_id` middleware.
  - usage/request/audit partition tables are not in `V1`.

## HMAC Verifier And Replay Slice

- **RED:** `mvn -pl gateway-runtime test` failed compilation because `HmacVerifier`, `NonceReplayGuard`, `JedisNonceReplayStore` and typed verification exceptions did not exist.
- **Verifier:** Strict lowercase signature format, inclusive `±300s` timestamp window, canonicalization and `MessageDigest.isEqual`.
- **Replay:** SHA-256 nonce key, 660-second TTL, atomic Redis `SET NX PX`, fail-closed store errors.
- **Ordering:** Signature and timestamp are verified before the nonce is claimed, preventing unauthenticated nonce-burning.
- **GREEN:** `mvn -pl gateway-runtime verify`
- **Tests:** 64 passed across canonicalizer, verifier, authenticator and replay store.
- **Coverage:** line 95.91% (352/367), branch 82.66% (205/248).
- **Real Redis evidence:** embedded Redis test executes concurrent claims; exactly one contender wins, and TTL is bounded.

## HMAC Authentication Filter Slice

- **RED:** `mvn -pl gateway-runtime test` initially could not execute the Filter tests because the test classpath lacked Spring Web; adding the test-only `spring-web` dependency exposed the Filter implementation contract.
- **HTTP boundary:** `/open/v1` and `/open/v1/**` require v1 HMAC headers, a 10-digit timestamp, a Host header and a uniquely supplied `Content-Length`.
- **Request handling:** raw bodies are capped at 1 MiB, cached for downstream consumption, and bounded even when `Content-Length` is absent.
- **Authentication order:** timestamp/signature verification occurs before the nonce claim. Resolver Secret arrays are defensive copies and are wiped after verification.
- **Error mapping:** malformed input returns 400, authentication failure/replay returns 401, oversized bodies return 413, configuration/runtime failure returns 500, and unavailable Redis/credential storage returns retryable 503.
- **Security RED:** an authenticated request with duplicate `Content-Length` headers returned 200; the expected result was 400 `DUPLICATE_HEADER`.
- **Security fix:** ambiguous `Content-Length` headers are rejected before body or signature processing.
- **GREEN:** `mvn verify`
- **Tests:** 86 gateway tests, including 22 Filter tests.
- **Coverage:** line 93.38% (494/529), branch 82.17% (258/314).
- **Follow-up at that checkpoint:** runtime registration and credential resolution are covered by the next slice below.

## Runtime Credential Resolution Slice

- **Database RED:** `mvn -pl platform-persistence -Dtest=ActiveCredentialLookupTest test` failed because `auth_resolve_active_credential(text)` did not exist.
- **Filter RED:** typed credential failures did not exist, so the Filter could not distinguish internal configuration failure from retryable credential-store/KMS failure.
- **Runtime RED:** `mvn -pl platform-app -am test` failed compilation because the Spring Boot application, JDBC resolver, KMS decryptor port and encryption context did not exist.
- **Database boundary:** `V2__active_credential_lookup.sql` adds a fixed-search-path `SECURITY DEFINER` function, revokes `PUBLIC`, accepts active/unexpired rotating credentials, and verifies active tenant/app plus credential expiry.
- **Resolver boundary:** `JdbcActiveCredentialResolver` uses a prepared statement, validates returned metadata and auth epochs, requires at least 32 plaintext bytes, and wipes rejected plaintext.
- **KMS boundary:** `CredentialSecretDecryptor` receives tenant/app/credential/AppKey/KMS-key context; retryable KMS failure maps to 503, deterministic decryption failure maps to 500, and absent adapters fail application startup.
- **Runtime:** `platform-app` registers the HMAC Filter in embedded Tomcat, uses a Jedis nonce store and produces an executable Spring Boot JAR.
- **End-to-end evidence:** `RuntimeHmacIntegrationTest` performs a signed HTTP request through Tomcat, PostgreSQL and Redis; verifies the downstream handler sees the authenticated AppKey; verifies Nonce replay returns 401; and verifies a suspended app fails before the controller.
- **GREEN:** `mvn verify`
- **Tests:** 17 `platform-app` tests and 3 `ActiveCredentialLookupTest` PostgreSQL tests.
- **Coverage:** runtime line 97.56% (80/82), branch 84.38% (27/32); gateway line 93.41% (510/546), branch 81.79% (265/324).
- **Known gap:** tests use a deterministic decryptor, not a concrete cloud KMS adapter. The production database role grant and request-level capacity also require staging validation.

## AWS KMS And Database Role Slice

- **RED:** `mvn -pl platform-app -am test` failed compilation because `AwsKmsCredentialSecretDecryptor`, role verification and KMS startup configuration did not exist.
- **AWS KMS:** The adapter sends stored KMS ciphertext with key ID and exact `tenantId/appId/credentialId/appKey` encryption context. A 3-second API timeout bounds dependency latency.
- **Failure classification:** KMS 429, 5xx and SDK transport failures map to retryable 503; invalid ciphertext, policy/key failures and empty plaintext map to non-retryable 500. KMS messages are not exposed.
- **Role verifier:** Startup rejects superuser and BYPASSRLS roles, requires `EXECUTE` on credential and authorization functions, and rejects direct `app_credential` DML. E2E connects as `gateway_staging`, rather than the database superuser.
- **GREEN:** `mvn -pl platform-app -am verify`
- **Tests:** 8 AWS KMS tests and 5 real PostgreSQL role tests at this checkpoint.
- **Git evidence:** RED `89fe275`; GREEN `539c653`.

## Application And API Authorization Slice

- **RED:** Filter authorization types were missing and PostgreSQL did not define `auth_authorize_public_api`.
- **Database:** V3 performs exact method/path matching, requires an ACTIVE PROD publication, enforces `TENANT_PRIVATE` tenant ownership, and checks an ACTIVE app grant.
- **Filter ordering:** Authorization runs after signature verification and Nonce claim. Missing grant maps to 403, inactive/foreign-private route to 404, credential race to 401, and authorization storage failure to retryable 503.
- **GREEN:** `mvn -pl platform-app -am verify`
- **Tests:** 4 PostgreSQL authorization tests, 5 JDBC gate tests and updated Filter/Tomcat integration tests.
- **Git evidence:** RED `df92e74`; GREEN `9f367db`.

## Pre-Authentication Rate Limit Slice

- **RED:** Pre-auth limiter types were missing and no limit ran before Header/body processing.
- **Redis algorithm:** One Lua command performs `INCR`, first-hit `PEXPIRE` and `PTTL`. Keys contain a fixed-window bucket and SHA-256 of `remoteAddr`.
- **HTTP boundary:** Allowed requests receive limit/remaining/reset Headers; denied requests receive 429, `Retry-After`, and retryable `RATE_LIMITED`; Redis failure is fail-closed 503.
- **Boundary RED:** `Duration.ofNanos(1)` passed construction and would divide by zero after millisecond truncation.
- **Boundary fix:** Rate-limit windows must be at least 1 ms.
- **GREEN:** `mvn verify`
- **Coverage:** gateway line 93.15% (626/672), branch 81.47% (321/394); runtime line 95.57% (194/203), branch 83.72% (72/86).
- **Git evidence:** RED `882e814`; GREEN `9797dd0`; boundary RED `ebd1614`; GREEN `3376f7e`.

## Post-Auth Limits And Quotas Slice

- **RED:** `mvn -pl platform-app -am test` failed compilation because post-auth policy, decision, Redis limiter and policy resolver types did not exist.
- **Policy data:** V4 adds `rate_limit_policy` and `quota_policy`, RLS, unique scope keys, `app_id` in authorization output and `auth_resolve_post_auth_policies(appId, apiId)`.
- **Tenant integrity RED/GREEN:** a database test first proved a policy owned by another tenant was incorrectly returned, then required application ownership matching and ignored the mismatched row after the fix.
- **Redis algorithm:** One Lua command captures one Redis `TIME`, reads application/API token buckets and UTC daily/monthly quotas, evaluates all six dimensions, and writes none if any dimension rejects.
- **HTTP boundary:** Authorization precedes post-auth limiting. `RATE_LIMITED`, `QUOTA_EXCEEDED`, standard headers, retry delay and retryable 503 mapping pass through the Filter.
- **Failure classification:** Partial token-bucket overrides fail as `INTERNAL_CONFIGURATION`; policy DB/Redis failure returns retryable `RATE_LIMIT_UNAVAILABLE` without internal details.
- **Quota semantics:** Application scope is global across credential rotation; API scope is global across applications and tenants. Token/quota counters are admission counters, not metered usage.
- **Cluster boundary:** The multi-key script targets one Redis endpoint. Redis Cluster remains unsupported until a cross-slot or two-phase protocol is designed and tested.
- **Staging arrangement:** `scripts/staging-security-smoke.ps1` covers valid, replay, token bucket, daily quota and monthly quota scenarios. Syntax, HMAC golden vector and missing-configuration fail-fast were checked locally.
- **Staging result:** NOT EXECUTED. No staging URL, Secret, AWS credentials or CLI access is configured in this workspace.
- **GREEN:** `mvn verify`
- **Result:** 229 tests, 0 failures, 0 errors, 0 skipped. Gateway line 93.83%, branch 82.32%; runtime line 95.35%, branch 82.31%.
- **Git evidence:** RED `a1e6dce`; GREEN `601a8b4`; staging harness `c157dff`.

## Route Template And Single API Proxy Slice

- **RED route/target:** `mvn -pl platform-app -am test` failed compilation because `AuthorizedApi` had no route-parameter snapshot, target types and lookup did not exist.
- **Route templates:** V5 validates literal/named segments, rejects duplicate parameter names, stores a generated route signature and prevents ambiguous method/signature pairs.
- **Precedence:** literal segments are compared left to right and win over parameter segments; the most specific published route is chosen before visibility/grant checks.
- **Target lookup:** `auth_resolve_api_target(apiId, apiVersionId)` returns only an ACTIVE published PROXY version, owner-matched ACTIVE endpoint and newest ACTIVE PROD environment.
- **Target failure classification:** invalid/missing target is non-retryable 502 `UPSTREAM_ERROR`; target database outage is retryable 503 `TARGET_STORE_UNAVAILABLE`.
- **RED proxy:** `mvn -pl platform-app -am test` failed compilation because proxy Filter, upstream client, request/response values and template expander did not exist.
- **Proxy behavior:** authorized requests are forwarded with route expansion, raw query and bounded body. Request/response Headers use allowlists; HMAC/Cookie/Host are not forwarded.
- **Failure mapping:** upstream transport and 5xx map to retryable 502 `UPSTREAM_ERROR`; timeout maps to 504 `UPSTREAM_TIMEOUT`; oversized response is bounded and non-retryable 502.
- **SSRF:** HTTPS-only, no userinfo/query/fragment/dot segments/encoded separators, no redirects, and literal loopback/private/link-local/reserved/CGNAT/IPv6 ULA targets are rejected.
- **E2E:** Embedded Tomcat receives a signed request for `/open/v1/probe/{probeId}`, resolves `probeId`, expands the target and reaches the injected upstream client with the expected `/upstream/probe-123` URI.
- **Known route gap:** percent-encoded route-parameter values are HMAC-canonicalized but not yet route-matched; public parameter values currently use unencoded safe characters.
- **Staging result:** NOT EXECUTED. DNS-backed private addresses, deployed egress policy, upstream `auth_ref`, real TLS and a real staging upstream remain unverified.
- **GREEN:** `mvn verify`
- **Result:** 265 tests, 0 failures, 0 errors, 0 skipped. Gateway line 93.72%, branch 82.40%; runtime line 94.71%, branch 81.69%.
- **Git evidence:** route/target RED `8023928`; GREEN `8e446be`; proxy RED `24c0409`; GREEN `1ba8503`.

## Git Checkpoints

| Slice | RED | GREEN | Follow-up |
| --- | --- | --- | --- |
| HMAC v1 | `7c24313` | `bc3d966` | `a634c35` RED, `80be7ae` security fix, `91312de` coverage |
| Publication guard | `e9db14a` | `ccdde7e` | `e2e230a` coverage |
| PostgreSQL foundation | `13fb211` | `f497eb9` | `c396e55` RED, `03b3976` revoke guard, `f5e9f22` RED, `030ac3f` commit-time guard |
| HMAC verifier/replay | `9a978c7` | `e4fd7d0` | `34db036` boundary hardening |
| HMAC authentication filter | `25fec7b` | `fe37c4f` | `c140907` RED, `e17b418` Content-Length hardening |
| Active credential lookup | `d286fc6` | `b22e22b` | Function, typed credential errors |
| Runtime gateway composition | `3e36dce` | `eaa0f08` | Spring Boot, JDBC resolver, KMS port, HTTP integration |
| AWS KMS and staging role | `89fe275` | `539c653` | Concrete decryptor, role startup verification |
| App/API authorization | `df92e74` | `9f367db` | V3 decision function and Filter gate |
| Pre-auth rate limit | `882e814` | `9797dd0` | `ebd1614` RED, `3376f7e` sub-ms boundary fix |
| Post-auth app/API limits and quotas | `a1e6dce` | `601a8b4` | Tenant/RLS and Redis-time hardening inside GREEN |
| Staging post-auth smoke harness | n/a | `c157dff` | Real staging execution remains blocked |
| Route templates and target lookup | `8023928` | `8e446be` | V5 route signature and target function |
| Single API proxy | `24c0409` | `1ba8503` | Header allowlist, SSRF baseline, 502/504; `75d31b9` root-locale normalization |

## Final Verification

- **Command:** `mvn verify`
- **Result:** BUILD SUCCESS
- **Contract tests:** 13 passed
- **Flow validator tests:** 21 passed
- **Gateway tests:** 143 passed
- **Publication guard tests:** 9 passed
- **PostgreSQL tests:** 24 passed
- **Runtime tests:** 55 passed
- **Total tests:** 265 passed, 0 failed, 0 errors, 0 skipped
- **Coverage:** orchestration line 92.98%/branch 82.81%; gateway line 93.72%/branch 82.40%; control line 100%/branch 95.00%; runtime line 94.71%/branch 81.69%

## Self Evaluation

| Axis | Score | Evidence |
| --- | --- | --- |
| Accuracy | 5 | OpenAPI parses, all 265 tests pass, PostgreSQL route/target/RLS constraints, AWS KMS request semantics, Redis quotas, real HTTP transport and a restricted-role Tomcat proxy path are exercised, and JaCoCo gates pass. |
| Completeness | 4 | Gate 0, HMAC, KMS, role verification, route templates, application/API authorization, pre/post-auth limits, published target lookup and single API proxy are complete. Real staging, DNS/egress enforcement, upstream auth injection, Redis Cluster, reconciliation, orchestration and usage/audit persistence remain future TDD slices. |
| Clarity | 4 | Contracts, test map and evidence report are linked and use stable error codes. The OpenAPI artifact is large and will benefit from generated documentation. |
| Actionability | 5 | `mvn verify` is the single validation command. The contract map identifies the next RED targets. |
| Conciseness | 4 | Test and contract artifacts are focused; the full OpenAPI file is large but serves as the authoritative consumer boundary. |

**Overall:** 4.5 / 5

**Highest-impact improvements:**

1. Execute the staging smoke and proxy runbook against real KMS, PostgreSQL, Redis, TLS, DNS/egress policy and an upstream.
2. Implement KMS/Vault-backed upstream `auth_ref`, two-instance proxy/load tests and usage reconciliation.
3. Add orchestration execution, control-plane management APIs/UI and usage/request/audit persistence.

**Self-check:** The 4.5 score reflects that authentication, authorization, quotas, route templates and a single-API proxy are verifiably complete locally, while real staging dependencies, DNS/egress controls, upstream credentials, control-plane workflows and orchestration are explicitly identified.
