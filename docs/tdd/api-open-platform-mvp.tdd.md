# API Open Platform MVP TDD Evidence

## Source

- Approved plan: `plans/api-open-platform-mvp.md`
- Contract map: `docs/tdd/api-open-platform-mvp.contract-map.md`
- Gate 0 contract: `docs/contracts/gate-0.md`

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
- **Unresolved High findings:** none.
- **Residual Medium items:**
  - HTTP HMAC verification, timestamp skew, nonce replay and constant-time comparison are not yet wired.
  - RLS depends on trusted `app.tenant_id` middleware.
  - usage/request/audit partition tables are not in `V1`.

## Git Checkpoints

| Slice | RED | GREEN | Follow-up |
| --- | --- | --- | --- |
| HMAC v1 | `7c24313` | `bc3d966` | `a634c35` RED, `80be7ae` security fix, `91312de` coverage |
| Publication guard | `e9db14a` | `ccdde7e` | `e2e230a` coverage |
| PostgreSQL foundation | `13fb211` | `f497eb9` | `c396e55` RED, `03b3976` revoke guard, `f5e9f22` RED, `030ac3f` commit-time guard |

## Final Verification

- **Command:** `mvn verify`
- **Result:** BUILD SUCCESS
- **Contract tests:** 12 passed
- **Flow validator tests:** 21 passed
- **HMAC tests:** 47 passed
- **Publication guard tests:** 9 passed
- **PostgreSQL foundation tests:** 10 passed
- **Total tests:** 99 passed, 0 failed, 0 errors, 0 skipped
- **Coverage:** orchestration line 92.98%/branch 82.81%; gateway line 96.99%/branch 83.64%; control line 100%/branch 95.00%

## Self Evaluation

| Axis | Score | Evidence |
| --- | --- | --- |
| Accuracy | 5 | OpenAPI parses, all 99 tests pass, PostgreSQL constraints are exercised, and JaCoCo gates pass. |
| Completeness | 4 | Gate 0, semantic validation, HMAC canonicalization, publication guard and DB foundation are complete. HTTP verifier, runtime execution and usage/audit persistence remain future TDD slices. |
| Clarity | 4 | Contracts, test map and evidence report are linked and use stable error codes. The OpenAPI artifact is large and will benefit from generated documentation. |
| Actionability | 5 | `mvn verify` is the single validation command. The contract map identifies the next RED targets. |
| Conciseness | 4 | Test and contract artifacts are focused; the full OpenAPI file is large but serves as the authoritative consumer boundary. |

**Overall:** 4.4 / 5

**Highest-impact improvements:**

1. Implement HMAC verification, nonce replay protection and timestamp skew before gateway routing.
2. Enforce DSL byte, node, depth and cumulative runtime budgets at the service boundary.
3. Add usage/request/audit partition migrations and provider-side OpenAPI response validation.

**Self-check:** The 4.4 score reflects that the requested Gate 0 and first code slice are verifiably complete, while unimplemented MVP runtime features are explicitly identified.
