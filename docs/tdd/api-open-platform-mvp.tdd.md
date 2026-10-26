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
- No Git repository exists; RED/GREEN evidence is preserved here instead of checkpoint commits.

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

## Final Verification

- **Command:** `mvn verify`
- **Result:** BUILD SUCCESS
- **Contract tests:** 12 passed
- **Flow validator tests:** 21 passed
- **Total tests:** 33 passed, 0 failed, 0 errors, 0 skipped
- **Flow validator coverage:** line 92.98% (212/228), branch 82.81% (106/128)

## Self Evaluation

| Axis | Score | Evidence |
| --- | --- | --- |
| Accuracy | 5 | OpenAPI parses, DSL fixtures validate as intended, all 33 tests pass, and JaCoCo gates pass. |
| Completeness | 4 | Gate 0 and the first semantic-validation slice are complete. Runtime execution, HMAC canonicalization, persistence, and HTTP providers remain future TDD slices. |
| Clarity | 4 | Contracts, test map and evidence report are linked and use stable error codes. The OpenAPI artifact is large and will benefit from generated documentation. |
| Actionability | 5 | `mvn verify` is the single validation command. The contract map identifies the next RED targets. |
| Conciseness | 4 | Test and contract artifacts are focused; the full OpenAPI file is large but serves as the authoritative consumer boundary. |

**Overall:** 4.4 / 5

**Highest-impact improvements:**

1. Implement HMAC v1 canonicalization with golden vectors before gateway routing.
2. Enforce DSL byte, node, depth and cumulative runtime budgets at the service boundary.
3. Add provider-side OpenAPI response validation once HTTP controllers exist.

**Self-check:** The 4.4 score reflects that the requested Gate 0 and first code slice are verifiably complete, while unimplemented MVP runtime features are explicitly identified.
