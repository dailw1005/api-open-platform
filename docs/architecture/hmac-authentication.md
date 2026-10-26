# HMAC v1 Authentication

## HTTP Boundary

`HmacAuthenticationFilter` protects `/open/v1` and `/open/v1/**`. Requests
outside that prefix pass through unchanged.

- A server-generated request ID is written to `X-Request-Id` and request
  attributes before authentication.
- The pre-authentication limiter runs before Header/body validation and uses
  the container-provided `remoteAddr`, never an unconfigured forwarded-for
  Header.
- Authentication headers must be present exactly once and use
  `X-Signature-Version: v1`.
- Duplicate `Host`, `Content-Length`, `Content-Type`, or HMAC headers are
  rejected to avoid proxy/container interpretation differences.
- Request bodies are cached before canonicalization so downstream handlers can
  read the original bytes. The default pre-authentication limit is 1 MiB.
- Unknown, disabled, expired, or revoked credentials resolve to the same
  `INVALID_CREDENTIAL` response, avoiding AppKey enumeration.

## Flow

1. Apply the pre-authentication per-IP fixed-window limit.
2. Validate unique and required headers, signature version, timestamp format
   and request size.
3. Read and cache the raw request body.
4. Resolve a defensive copy of the active Secret.
5. Canonicalize the request using `HmacCanonicalizer`.
6. Reject timestamps outside the inclusive `±300s` window.
7. Recompute HMAC-SHA256 and compare with `MessageDigest.isEqual`.
8. Atomically claim the app/nonce pair in Redis with `SET NX PX`.
9. Resolve the exact published method/path and require an ACTIVE app grant.
10. Atomically check application/API token buckets and application/API daily
    and monthly quotas.
11. Attach authenticated identity and the authorized API snapshot, then pass
    the request to routing.

The nonce is deliberately claimed after signature verification so an
unauthenticated caller cannot burn a valid client's nonce. The resolved Secret
array is wiped in a `finally` block after verification.

## Nonce Key

```text
apip:auth:nonce:v1:<sha256(appKey + NUL + nonce)>
```

- Hashing bounds key length and avoids exposing raw nonce values in operational
  tooling.
- Default TTL is `660s`: two 300-second timestamp windows plus 60 seconds of
  clock/network leeway.
- `SET NX PX` is a single atomic Redis command; concurrent attempts have exactly
  one winner.
- Redis errors fail closed. A request is not accepted if replay protection is
  unavailable.

## Redis Requirements

- Use an isolated Redis logical database or instance for nonce/security state.
- Set `maxmemory-policy noeviction`; evicting nonce keys would weaken replay
  protection.
- Enable authentication and TLS for non-local deployments.
- Apply connection and command timeouts; never retry a nonce claim blindly.
- Current implementation targets one Redis endpoint. Cluster and sentinel
  deployment are later operational slices.

## Pre-Authentication Rate Limit

The default limit is 120 requests per 60-second fixed window and is keyed by:

```text
apip:rate:preauth:v1:<window-bucket>:<sha256(remoteAddr)>
```

A single Lua command performs `INCR`, first-hit `PEXPIRE` and `PTTL`, so one
Redis round trip returns the count and reset time. Allowed requests receive
`X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`.
Rejected requests additionally receive `Retry-After` and HTTP 429.

Redis failure is fail-closed as retryable 503. The current fixed window is a
coarse anti-abuse control: bursts at a window boundary can reach approximately
twice the configured limit. It remains the first abuse-control layer; the
post-authentication limits below run after signature and authorization checks.

## Credential Decryption

`AwsKmsCredentialSecretDecryptor` sends the stored KMS ciphertext blob directly
to AWS KMS. The request contains the stored KMS key ID and this exact encryption
context:

```text
tenantId, appId, credentialId, appKey
```

KMS 429/5xx responses and SDK transport failures map to retryable 503.
Invalid ciphertext, key/policy failures, empty plaintext and other deterministic
errors map to non-retryable 500 without exposing the KMS message.

KMS configuration uses `gateway.security.kms.region`,
`gateway.security.kms.endpoint-override` and a 3-second default
`gateway.security.kms.api-call-timeout`. Production uses the AWS default
credentials provider chain and a key policy scoped to the gateway workload.

## Application And API Authorization

Authorization runs only after signature verification and Nonce claim.
`auth_authorize_public_api(appKey, method, path)` uses an exact method/path
match and returns:

- `API_NOT_GRANTED` when the published API exists but no ACTIVE app grant does;
- `API_NOT_FOUND` when the route is not actively published or a
  `TENANT_PRIVATE` API belongs to another tenant;
- `INVALID_CREDENTIAL` if the credential state changed between authentication
  and authorization;
- `ALLOWED` with application, API, version, tenant and visibility metadata.

The credential, authorization and policy lookup functions are `SECURITY
DEFINER`, revoke `PUBLIC`, and must be granted to the non-superuser gateway
role.

## Post-Authentication Limits And Quotas

Post-authentication limits run after the nonce claim and exact-route
authorization. Application limits use `app_id`, while API limits use `api_id`
and are global across applications and tenants.

The effective policy combines database overrides with mandatory process
defaults:

- application and API token buckets: sustained token rate, window and burst;
- application and API quotas: UTC daily and monthly `CALLS`.

`rate_limit_policy` and `quota_policy` overrides are read through
`auth_resolve_post_auth_policies(appId, apiId)`. An omitted application or API
policy falls back to the configured defaults; an incomplete token-bucket
override or malformed database value fails closed as
`INTERNAL_CONFIGURATION`.

One Redis Lua command checks all six counters before writing any state:

```text
app token bucket
API token bucket
app daily quota
app monthly quota
API daily quota
API monthly quota
```

If any layer rejects, no token or quota counter is consumed. Redis `TIME` is
captured once and passed into the script so token refill, UTC period keys and
expiry boundaries use the same server-derived instant.

Keys are scoped by stable identifiers:

```text
apip:limit:postauth:v1:token:app:<appId>
apip:limit:postauth:v1:token:api:<apiId>
apip:limit:postauth:v1:quota:app:<appId>:<day|month>:<period>
apip:limit:postauth:v1:quota:api:<apiId>:<day|month>:<period>
```

Allowed requests receive `X-RateLimit-*` for the currently most constrained
layer, replacing the coarser pre-auth values. A token-bucket rejection returns
429 `RATE_LIMITED`; a daily or monthly rejection returns 429
`QUOTA_EXCEEDED`. Both include `Retry-After`. Redis or policy-source failure is
retryable 503 `RATE_LIMIT_UNAVAILABLE`.

Counters are admission counters. They are consumed when the request passes all
authentication/authorization/limit gates, before routing. Upstream usage,
billing and periodic quota reconciliation remain separate metering work.

The multi-key Lua operation currently targets one Redis endpoint, not Redis
Cluster. A Cluster deployment must not silently split these checks; it requires
an explicitly designed shared-slot or two-phase reservation strategy.

## Error Contract

All Filter errors use the stable JSON envelope:

```json
{
  "code": "INVALID_SIGNATURE",
  "message": "Signature verification failed",
  "requestId": "server-generated-id",
  "retryable": false
}
```

| HTTP | Codes | Retryable |
| --- | --- | --- |
| 400 | `INVALID_REQUEST`, `INVALID_TIMESTAMP_FORMAT`, `UNSUPPORTED_SIGNATURE_VERSION`, `INVALID_CONTENT_LENGTH`, `DUPLICATE_HEADER`, `MISSING_HOST`, `REQUEST_READ_FAILED` | false |
| 401 | `MISSING_AUTH_HEADER`, `INVALID_SIGNATURE_FORMAT`, `INVALID_SIGNATURE`, `TIMESTAMP_OUT_OF_WINDOW`, `NONCE_REPLAYED`, `INVALID_CREDENTIAL` | false |
| 403 | `API_NOT_GRANTED` | false |
| 404 | `API_NOT_FOUND` | false |
| 413 | `REQUEST_TOO_LARGE` | false |
| 429 | `RATE_LIMITED`, `QUOTA_EXCEEDED` | true |
| 500 | `INTERNAL_CONFIGURATION`, `INTERNAL_ERROR` | false |
| 503 | `NONCE_STORE_UNAVAILABLE`, `CREDENTIAL_STORE_UNAVAILABLE`, `AUTHORIZATION_STORE_UNAVAILABLE`, `RATE_LIMIT_UNAVAILABLE` | true |

Error responses never include the Secret, provided Signature, stack traces,
credential-store details, or internal configuration.

## Runtime Integration

`platform-app` is the runtime composition root. It starts Spring Boot with
embedded Tomcat, registers `HmacAuthenticationFilter` through
`FilterRegistrationBean`, creates the Jedis-backed nonce store and wires a
JDBC `ActiveCredentialResolver`.

The resolver calls the PostgreSQL `auth_resolve_active_credential(text)`
`SECURITY DEFINER` function. That function permits AppKey lookup without a
pre-existing tenant session, but returns rows only when:

- the credential status is `ACTIVE` or valid overlap `ROTATING`;
- the app and tenant are `ACTIVE`;
- `expires_at` is null or in the future.

The function has a fixed safe `search_path`, is not executable by `PUBLIC`, and
must be granted only to the gateway database role. The resolver validates
credential metadata and auth epochs, calls the `CredentialSecretDecryptor` port,
requires a plaintext Secret of at least 32 bytes, and wipes invalid plaintext
before failing closed.

The concrete AWS KMS decryptor is enabled by default. The application
intentionally fails startup when KMS configuration or a decryptor bean is
unavailable. There is no Secret cache, so revocations and expiration take effect
on the next request. A bounded cache may be added later only with
credential/app epoch validation and a strict maximum staleness window.

Startup also verifies that the connected database role is not superuser, does
not have `BYPASSRLS`, can execute the credential, authorization and post-auth
policy functions, and cannot select or mutate `app_credential` directly.

## Remaining Production Work

- Run AWS KMS decryption and the role verifier against the real staging account,
  key policy, database login role and network path.
- Configure trusted reverse-proxy client-IP extraction or ingress-level
  rate limiting; direct `remoteAddr` is only correct when the gateway is the
  network edge.
- Add bounded request concurrency, distributed Redis Cluster coordination,
  multi-instance load tests and quota reconciliation from immutable usage.
- Replace exact path matching with reviewed route-template resolution.
- Add route resolution, upstream proxy/orchestration dispatch, metering and
  sanitized request logging.
