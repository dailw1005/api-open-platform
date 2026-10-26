# OpenAPI Gate 0

## Status

- Status: Accepted
- Source plan: `plans/api-open-platform-mvp.md`
- Confirmed defaults: 2026-10-23
- Production implementation: Not started

## Boundary Ownership

| Boundary | Authoritative artifact | Consumer | Provider owner |
| --- | --- | --- | --- |
| HTTP management and developer API | `contracts/openapi/openapi.yaml` | Vue management portal, developer portal, generated clients | Platform backend |
| Public gateway | `contracts/openapi/openapi.yaml` | External applications and SDKs | Gateway runtime |
| Orchestration DSL v1 | `contracts/dsl/orchestration-dsl-v1.schema.json` | DSL editor, compiler, validator, tests | Orchestration engine |

No handwritten request/response DTO or DSL model is authoritative before these artifacts are reviewed.

## Consumer Jobs

1. A platform administrator can sign in, create a tenant, register an upstream, publish a single API, review a tenant orchestration, and inspect audit records.
2. An application developer can create an app, receive an AppKey/Secret once, grant a published API, validate and test an orchestration draft, and submit it for review.
3. An external application can calculate an HMAC v1 signature and receive a normalized success or error response through `/open/v1/**`.
4. A viewer can list published APIs and orchestrations, app metadata, usage, and sanitized logs without any write capability.
5. A platform administrator can suspend a tenant/app, revoke a credential, offline an API, and have subsequent protected calls fail closed.

## Contract Conventions

- HTTP contract version: OpenAPI `3.1.0`.
- Resource identifiers are opaque strings with UUID format.
- Timestamps are RFC 3339 UTC strings.
- Monetary amounts are decimal strings; clients must not parse them into binary floating point.
- Errors always use `ErrorResponse`.
- Session writes require both the session cookie and `X-CSRF-Token`.
- Retryable state-changing operations require `Idempotency-Key`.
- Every operation declares `operationId`, `x-auth-kind`, `x-required-role`, `x-tenant-scope`, `x-csrf-required`, and `x-idempotency`.
- Public gateway paths are dynamic after `/open/v1/`; the contract describes method, authentication, headers, and response envelopes, not individual business APIs.
- Breaking contract changes require a new API version. Additive optional fields are allowed within a version.

## Route and Permission Matrix

| Route group | Authentication | Role | Tenant scope | CSRF | Idempotency |
| --- | --- | --- | --- | --- | --- |
| `/platform-admin/v1/sessions` | None | NONE | GLOBAL | No | Optional |
| `/platform-admin/v1/**` reads | Session | PLATFORM_ADMIN | GLOBAL/TENANT | No | None |
| `/platform-admin/v1/**` writes | Session | PLATFORM_ADMIN | GLOBAL/TENANT | Yes | Required for publication, review, rollback and policy changes |
| `/developer/v1/sessions` | None | NONE | GLOBAL | No | Optional |
| `/developer/v1/**` reads | Session | APP_DEVELOPER or VIEWER | TENANT/RESOURCE_OWNER | No | None |
| `/developer/v1/**` writes | Session | APP_DEVELOPER | TENANT/RESOURCE_OWNER | Yes | Required for credential and test-run creation |
| `/open/v1/**` | HMAC v1 | Application identity | RESOURCE_OWNER | No | Optional |

Viewer access is read-only and cannot be used as an implicit grant to write. Developer visibility to app-owned resources is narrower than viewer tenant-wide read visibility.

## State Guards

- Developers can transition orchestration `DRAFT -> VALIDATED -> IN_REVIEW`.
- Platform administrators can transition orchestration `IN_REVIEW -> PUBLISHED` or back to `DRAFT`.
- Only platform administrators can create API publications, roll back active production publications, deprecate APIs, and offline APIs.
- Credentials are shown once at creation/rotation and can never be read again.
- A `TENANT_PRIVATE` API can only be granted to an app in the same tenant.
- A private app resource requires same-tenant access and, for writes, the app owner.

## Contract Test Evidence

Gate 0 is accepted only after all checks below pass:

- OpenAPI parses without errors and every required operation exists.
- Every operation declares the contract extensions and normalized error responses.
- Session writes declare both session and CSRF security.
- Public gateway operations declare HMAC v1 and all signature headers.
- DSL Schema passes meta-schema validation.
- Valid DSL example passes schema validation.
- Structural invalid DSL fixtures are rejected.
- Semantic rules that JSON Schema cannot express are listed in `docs/tdd/api-open-platform-mvp.contract-map.md` for RED-first validator tests.

## Verification

- **Command:** `mvn test`
- **Result:** PASS
- **Contract tests:** 12 passed, 0 failed, 0 errors
- **Coverage for semantic validator:** line 92.98%, branch 82.81%

## Open Contract Decisions

None blocking. P2 refinements remain limited to implementation details recorded in the MVP plan.
