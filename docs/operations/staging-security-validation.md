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
- has no direct `SELECT`, `INSERT`, `UPDATE` or `DELETE` on `app_credential`.

Capture the startup verification result and the deployed role name. A successful
embedded test is not a substitute for this staging run.

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

## Redis Gate

- Redis uses TLS and authentication outside localhost.
- `maxmemory-policy` is `noeviction`.
- Nonce and pre-auth rate-limit keys use the isolated security instance/logical
  database.
- Connection and command timeouts are bounded.
- Redis unavailability returns fail-closed retryable errors, never bypasses
  nonce or rate-limit checks.

## Client IP Gate

The current limiter uses Servlet `remoteAddr`. Validate one of these deployment
models:

- the gateway is the network edge and `remoteAddr` is the client address; or
- a trusted ingress enforces the authoritative per-IP limit and the application
  receives the correct forwarded address through an explicitly reviewed proxy
  configuration.

Never accept arbitrary client-supplied forwarding Headers. Document the ingress
hop count, proxy allowlist and Header rewrite rule.

## Acceptance

- Runtime starts only with the least-privilege database role.
- Real staging KMS decrypt succeeds and invalid ciphertext fails closed.
- Nonce replay returns 401.
- Missing app/API grant returns 403.
- Unknown/unpublished route returns 404.
- Exceeded pre-auth limit returns 429 with rate-limit Headers.
- Redis/KMS/database outages return stable retryable or non-retryable errors
  without secrets or internal details.
