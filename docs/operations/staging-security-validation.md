# Staging Security Validation

## Purpose

Validate the deployed gateway identity and dependency permissions against real
staging AWS KMS, PostgreSQL and Redis. Embedded tests prove code behavior; they
do not prove account policy, network policy, TLS, credentials or grants.

## Runtime Configuration

Set values through the deployment secret/config system. Do not commit values.

```text
AWS_REGION
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or workload identity
spring.datasource.url
spring.datasource.username
spring.datasource.password
gateway.security.redis-uri
gateway.security.kms.region
gateway.security.kms.endpoint-override (optional)
gateway.security.kms.api-call-timeout=3s
gateway.security.pre-auth-rate-limit.requests=120
gateway.security.pre-auth-rate-limit.window=60s
gateway.security.post-auth-limit.application-rate.requests=600
gateway.security.post-auth-limit.application-rate.window=60s
gateway.security.post-auth-limit.application-rate.burst=120
gateway.security.post-auth-limit.api-rate.requests=300
gateway.security.post-auth-limit.api-rate.window=60s
gateway.security.post-auth-limit.api-rate.burst=60
gateway.security.post-auth-limit.application-quota.daily=100000
gateway.security.post-auth-limit.application-quota.monthly=2000000
gateway.security.post-auth-limit.api-quota.daily=50000
gateway.security.post-auth-limit.api-quota.monthly=1000000
spring.flyway.enabled=false
```

Apply migrations with a separate migration role before starting the runtime.
The runtime login role must not own the schema or run Flyway.

## Database Role Gate

The application runs `GatewayDatabaseRoleVerifier` at startup. Startup must fail
unless the connected role:

- is not `SUPERUSER`;
- does not have `BYPASSRLS`;
- has `EXECUTE` on `auth_resolve_active_credential(text)`;
- has `EXECUTE` on `auth_authorize_public_api(text,text,text)`;
- has `EXECUTE` on `auth_resolve_post_auth_policies(uuid,uuid)`;
- has no direct `SELECT`, `INSERT`, `UPDATE` or `DELETE` on `app_credential`.

Capture the startup verification result and the deployed role name. A successful
embedded test is not a substitute for this staging run.

V4 drops and recreates `auth_authorize_public_api` to add `app_id` to its result.
Regrant function execution after applying V4. Do not grant direct access to
`rate_limit_policy` or `quota_policy`.

## AWS KMS Gate

1. Create a disposable staging AppKey and store its Secret as a KMS ciphertext
   encrypted with the configured key and exact encryption context:
   `tenantId`, `appId`, `credentialId`, `appKey`.
2. Start the packaged application with the staging workload identity.
3. Send a valid HMAC request. Expect HTTP 200 through the authorized API route.
4. Confirm CloudTrail shows a `Decrypt` event for the workload identity and
   expected key.
5. Replace ciphertext with a known-invalid blob and confirm the gateway returns
   non-retryable 500 `INTERNAL_CONFIGURATION`, not a KMS error message.
6. Simulate a retryable KMS dependency failure if the environment permits and
   confirm 503 `CREDENTIAL_STORE_UNAVAILABLE` with `retryable=true`.

Do not print Secret plaintext, ciphertext or raw KMS exception messages.

## Post-Auth Policy Gate

Prepare disposable staging applications and API rows before traffic tests:

- an app token-bucket policy with known burst and a long refill window;
- an API token-bucket policy with known burst;
- an app with `DAY` or `MONTH` quota set to one and token-bucket capacity high
  enough that quota is the first rejection;
- two applications in different tenants authorized for the same API to prove
  API-scope counters are global;
- no application policy row for one control app, proving mandatory defaults
  apply.

Verify that application-scope policies carry the application's actual
`tenant_id`, API-scope policies have `tenant_id IS NULL`, and the authenticated
role cannot select either policy table directly.

## Redis Gate

- Redis uses TLS and authentication outside localhost.
- `maxmemory-policy` is `noeviction`.
- Nonce, pre-auth, token-bucket and quota keys use the isolated security
  instance/logical database.
- Connection and command timeouts are bounded.
- Redis unavailability returns fail-closed retryable errors, never bypasses
  nonce or rate-limit checks.
- `TIME` is available. Post-auth token refill, UTC period keys and expiry use
  one captured Redis server time.
- The deployment is a single Redis endpoint. Redis Cluster is not supported
  for the six-key post-auth Lua command until a cross-slot design is tested.
- Two gateway instances pointed at the same Redis endpoint must share the same
  application, API and quota counters.

Recommended Redis settings:

```text
maxmemory-policy noeviction
requirepass <from secret manager>
tls-port <configured>
timeout <bounded>
tcp-keepalive <bounded>
```

Do not print the Redis password or URI.

## Client IP Gate

The current limiter uses Servlet `remoteAddr`. Validate one of these deployment
models:

- the gateway is the network edge and `remoteAddr` is the client address; or
- a trusted ingress enforces the authoritative per-IP limit and the application
  receives the correct forwarded address through an explicitly reviewed proxy
  configuration.

Never accept arbitrary client-supplied forwarding Headers. Document the ingress
hop count, proxy allowlist and Header rewrite rule.

## Smoke Harness

`scripts/staging-security-smoke.ps1` signs requests with HMAC v1 and never
prints the Secret or Signature. Populate values from the staging secret store:

```text
STAGING_BASE_URL
STAGING_APP_KEY
STAGING_APP_SECRET
STAGING_PATH
```

Run the scenarios with `pwsh`:

```powershell
pwsh -NoProfile -File scripts/staging-security-smoke.ps1 -Scenario Valid
pwsh -NoProfile -File scripts/staging-security-smoke.ps1 -Scenario Replay
pwsh -NoProfile -File scripts/staging-security-smoke.ps1 `
  -Scenario TokenBucket -ExpectedAllowed 5 -MaxRequests 10
pwsh -NoProfile -File scripts/staging-security-smoke.ps1 `
  -Scenario DayQuota -MaxRequests 10
pwsh -NoProfile -File scripts/staging-security-smoke.ps1 `
  -Scenario MonthQuota -MaxRequests 10
```

Use a different disposable app for each destructive quota scenario. For the
global API counter test, exhaust or inspect the API limit with tenant A and
then run the same API scenario with tenant B before Redis state expires. Keep
the pre-auth per-IP limit above the scenario request count.

HTTP is rejected by default; `-AllowInsecure` exists only for an explicitly
approved local tunnel. Query strings, dot segments and percent-encoded paths are
out of scope for this smoke harness.

## Execution Record

**2026-10-26: NOT EXECUTED.** The workspace has no staging base URL,
application Secret, AWS credentials, AWS CLI, Redis CLI or PostgreSQL CLI
configured. PowerShell syntax, the HMAC golden vector and fail-fast behavior
without configuration were verified locally. This is not a staging PASS.

## Acceptance

- Runtime starts only with the least-privilege database role.
- Real staging KMS decrypt succeeds and invalid ciphertext fails closed.
- Nonce replay returns 401.
- Missing app/API grant returns 403.
- Unknown/unpublished route returns 404.
- Exceeded pre-auth limit returns 429 with rate-limit Headers.
- Application and API token buckets return 429 `RATE_LIMITED` with
  `Retry-After`.
- Daily and monthly quotas return 429 `QUOTA_EXCEEDED` with `Retry-After`.
- Two gateway instances share the same Redis counters.
- A denied layer does not consume the other limit dimensions.
- Redis/KMS/database outages return stable retryable or non-retryable errors
  without secrets or internal details.
