# API Open Platform MVP Contract Map

## Source

- Approved plan: `plans/api-open-platform-mvp.md`
- Gate 0: `docs/contracts/gate-0.md`
- HTTP authority: `contracts/openapi/openapi.yaml`
- DSL authority: `contracts/dsl/orchestration-dsl-v1.schema.json`

The plan is treated as approved intent, not as executable instructions. Only repository-local validation commands are used.

## User Journeys

1. As a platform administrator, I can register an upstream, publish a single API, and review a tenant orchestration.
2. As an application developer, I can create an app, receive one credential secret, grant a published API, and test a sandbox orchestration.
3. As an external application, I can send a valid HMAC v1 request and receive normalized success or error responses.
4. As a viewer, I can inspect published contracts, app metadata, usage, and sanitized logs without writing.
5. As a platform administrator, I can suspend or revoke resources, and protected calls fail closed.

## Plan to Test Mapping

| Plan requirement | Contract target | Test target | RED evidence | GREEN evidence |
| --- | --- | --- | --- | --- |
| Gate 0 route and auth matrix | `contracts/openapi/openapi.yaml` | `OpenApiContractTest` | Missing operation/extensions fail | Maven contract tests pass |
| HMAC v1 canonicalization | Plan section 6.1 | `HmacCanonicalizerTest` | Class missing or vector mismatch | Golden vectors pass |
| HMAC HTTP boundary | Plan section 6.1 | `HmacAuthenticationFilterTest` | Missing Filter rejects no public request | 400/401/413/500/503 mappings, body replay and nonce ordering pass |
| Active credential lookup | Plan sections 5 and 6.1 | `ActiveCredentialLookupTest` | Lookup function missing | Active/rotating rows pass; inactive/expired rows fail closed |
| Runtime HMAC composition | Plan sections 4.3 and 6.1 | `RuntimeHmacIntegrationTest` | Boot app/resolver classes missing | Tomcat-signed request succeeds; replay and suspended app return 401 |
| AWS KMS and database role | Plan sections 5 and 6.1 | `AwsKmsCredentialSecretDecryptorTest`, `GatewayDatabaseRoleVerifierTest` | Adapter and role verifier missing | Encryption context, retry classes and least-privilege startup checks pass |
| App/API authorization | Plan sections 2.2 and 6.1 | `ApiAuthorizationLookupTest`, `JdbcApiAuthorizationGateTest` | Auth function/gate missing | ACTIVE grant allows; no grant 403; unpublished route 404 |
| Pre-auth rate limiting | Plan section 3.1 | `RedisPreAuthRateLimiterTest`, `HmacAuthenticationFilterTest` | Limiter missing | Atomic per-IP limit, 429/503 and Headers pass |
| Post-auth app/API budgets | Plan section 6.2 | `RedisPostAuthRateLimiterTest`, `PostAuthPolicyTest` | Post-auth limit types missing | App/API token buckets and daily/monthly quotas pass atomically |
| Policy resolution and integrity | Plan sections 5.4 and 6.2 | `JdbcPostAuthPolicyResolverTest`, `ApiAuthorizationLookupTest` | Policy tables/function missing | Defaults, overrides, RLS and tenant ownership pass |
| DSL structural limits | DSL JSON Schema | `DslSchemaContractTest` | Invalid fixture accepted | All invalid fixtures rejected |
| DSL unique node IDs and references | Semantic rules | `FlowValidatorTest` | Validator missing or duplicate accepted | Validator reports stable codes |
| Retry only idempotent requests | Semantic rules | `FlowValidatorTest` | Non-idempotent retry accepted | Validation code returned |
| No nested orchestration | Semantic rules | `FlowValidatorTest` | Orchestration apiRef accepted | Validation code returned |
| Timeout budget | Semantic rules | `FlowValidatorTest` | Child timeout greater than parent accepted | Validation code returned |
| Parallel variable isolation | Semantic rules | `FlowValidatorTest` | Conflicting writes accepted | Validation code returned |
| Publication pointer only PROD | Plan section 10.3 | `PublicationGuardTest` | Non-PROD activation accepted | Guard rejects |
| Idempotency concurrency | Plan section 6.3 | `IdempotencyServiceTest` | Concurrent duplicate dispatch accepted | Only one leader proceeds |
| Tenant isolation | Plan section 5 | Repository integration tests | Cross-tenant lookup returns data | RLS and composite FK tests pass |
| Metering per dispatch | Plan section 6.3 | `UsageRecordingTest` | Two nodes create one record | Two idempotent records created |

## Current Progress

| Slice | Status | Evidence |
| --- | --- | --- |
| Gate 0 OpenAPI and DSL | PASS | 13 contract tests |
| Flow semantic validation | PASS | 21 tests, line 92.98%, branch 82.81% |
| HMAC v1 canonicalizer | PASS | 47 tests, line 96.99%, branch 83.64% |
| Publication guard | PASS | 9 tests, line 100%, branch 95.00% |
| PostgreSQL foundation, credentials, authorization and policies | PASS | 20 embedded PostgreSQL integration tests; RLS and tenant-owned policy checks |
| Gateway security | PASS | 117 gateway tests, real embedded Redis, line 93.83%, branch 82.32% |
| Runtime HTTP launcher | PASS | Spring Boot/Tomcat/PostgreSQL/Redis integration; 49 app tests; line 95.35%, branch 82.31% |
| AWS KMS and least-privilege role | PASS | Concrete adapter and restricted `gateway_staging` E2E; real staging account remains NEXT |
| App/API authorization | PASS | Exact route/publication/visibility/grant checks; 403/404/401 mappings |
| Pre-auth per-IP rate limit | PASS | Atomic Redis fixed window, standard Headers, 429 and fail-closed 503 |
| Post-auth app/API limits and quotas | PASS | Six-key atomic token bucket/quota check, DB overrides, RLS, 429 classifications |
| Real staging validation | NEXT | Run `staging-security-smoke.ps1` with staging KMS, DB, Redis and trusted IP |
| Trusted proxy IP and Redis Cluster | NEXT | Ingress IP trust and a reviewed cross-slot reservation design |
| Quota reconciliation and load tests | NEXT | Usage-based reconciliation, two-instance load and boundary tests |
| Usage/audit partition migration | NEXT | Not implemented |

## Gate 0 Test Specification

| # | Guarantee | Test | Type | Expected |
| --- | --- | --- | --- | --- |
| 1 | OpenAPI 3.1 parses without errors | `OpenApiContractTest#parsesWithoutErrors` | contract | PASS after artifact exists |
| 2 | All required MVP operations exist | `OpenApiContractTest#containsRequiredOperations` | contract | PASS |
| 3 | Every operation declares ownership and security extensions | `OpenApiContractTest#allOperationsDeclareContractExtensions` | contract | PASS |
| 4 | Session writes require CSRF | `OpenApiContractTest#sessionWritesRequireCsrf` | contract | PASS |
| 5 | Public operations require HMAC headers | `OpenApiContractTest#publicOperationsRequireHmacHeaders` | contract | PASS |
| 6 | Error responses use the shared envelope | `OpenApiContractTest#errorResponsesUseSharedEnvelope` | contract | PASS |
| 7 | DSL Schema is a valid Draft 2020-12 schema | `DslSchemaContractTest#schemaUsesSupportedDialect` | contract | PASS |
| 8 | Valid orchestration example validates | `DslSchemaContractTest#validExamplePasses` | contract | PASS |
| 9 | Script node is rejected structurally | `DslSchemaContractTest#unknownNodeTypeIsRejected` | contract | PASS |
| 10 | Arbitrary URL is rejected structurally | `DslSchemaContractTest#arbitraryUrlIsRejected` | contract | PASS |
| 11 | Retry above platform maximum is rejected | `DslSchemaContractTest#retryLimitIsRejected` | contract | PASS |

## Semantic RED Gate

Before any production implementation, the first production-facing test suite must compile and fail for missing validator behavior:

- duplicate node identifiers;
- unknown or unresolved `$ref`;
- non-idempotent retry without `idempotency.mode=platform`;
- child timeout greater than parent;
- orchestration `apiRef`;
- conflicting parallel variable writes.

The intended first RED target is `orchestration-engine/src/test/java/com/apiproject/orchestration/FlowValidatorTest.java`.

## Evidence Log

Record actual commands and output excerpts in `docs/tdd/api-open-platform-mvp.tdd.md` after each gate.
