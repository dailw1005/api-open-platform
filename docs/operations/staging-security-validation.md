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
- has `EXECUTE` on `auth_resolve_api_target(uuid,uuid)`;
- has no direct `SELECT`, `INSERT`, `UPDATE` or `DELETE` on `app_credential`.

Capture the startup verification result and the deployed role name. A successful
embedded test is not a substitute for this staging run.

V4 and V5 drop and recreate `auth_authorize_public_api`, adding `app_id` and
route parameters. Regrant function execution after applying the latest
migration. Do not grant direct access to policy or upstream tables.

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

## Single API Proxy Gate

Prepare one published `PROXY` API with:

- a literal route and a templated route;
- a matching ACTIVE `api_version` and PROD publication;
- an upstream endpoint owned by the API owner;
- an ACTIVE PROD `upstream_environment` with an HTTPS base URL;
- `config_json.upstreamEndpointId` pointing to that endpoint.

Verify:

- `/users/me` resolves the literal route before `/users/{userId}`;
- `/users/user-123` returns `userId=user-123` and expands the upstream path;
- an unpublished, inactive or cross-owner upstream does not resolve;
- HMAC, Cookie, Host and hop-by-hop request Headers are not forwarded;
- only the documented response Header allowlist reaches the client;
- query strings and up to 1 MiB of body are forwarded unchanged;
- upstream redirects are not followed;
- upstream 5xx becomes 502 `UPSTREAM_ERROR`;
- timeout becomes 504 `UPSTREAM_TIMEOUT`;
- oversized upstream response becomes bounded 502 `UPSTREAM_ERROR`;
- database target lookup failure becomes retryable 503
  `TARGET_STORE_UNAVAILABLE`.

The current adapter does not inject `upstream_environment.auth_ref`. Use only a
staging upstream that requires no gateway-injected credential, or terminate the
test with a documented failure. Do not put an upstream Secret in
`api_version.config_json`.

## SSRF And Egress Gate

- Confirm staging rejects literal loopback, private, link-local, multicast,
  carrier-grade NAT and IPv6 unique-local targets.
- Resolve the configured DNS name from the gateway egress network and confirm
  every answer is a reviewed public address.
- Enforce a network egress allowlist or private-address firewall. Application
  validation alone cannot close DNS rebinding or hostile DNS answers.
- Confirm redirects are disabled.
- Confirm `upstream_environment.egress_zone` and `tls_policy` map to deployed
  network policy. Those columns are not enforced by the current Java client.

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

**2026-10-27: NOT EXECUTED.** The workspace has no staging base URL,
application Secret, AWS credentials, AWS CLI, Redis CLI or PostgreSQL CLI
configured. PowerShell syntax, the HMAC golden vector and fail-fast behavior
without configuration were verified locally. Embedded PostgreSQL/Redis/Tomcat,
route templates and injected HTTP client tests pass, but no real staging
upstream, DNS/egress policy, TLS trust or upstream credential was exercised.
This is not a staging PASS.

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
- A signed templated route reaches the intended ACTIVE PROD upstream.
- Literal route precedence and duplicate-route rejection are verified.
- Auth/cookie headers are stripped and upstream response Headers are allowlisted.
- DNS/private-address egress controls and redirect blocking are verified.
- Redis/KMS/database outages return stable retryable or non-retryable errors
  without secrets or internal details.
