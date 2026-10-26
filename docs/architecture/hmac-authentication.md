# HMAC v1 Authentication

## HTTP Boundary

`HmacAuthenticationFilter` protects `/open/v1` and `/open/v1/**`. Requests
outside that prefix pass through unchanged.

- A server-generated request ID is written to `X-Request-Id` and request
  attributes before authentication.
- Authentication headers must be present exactly once and use
  `X-Signature-Version: v1`.
- Duplicate `Host`, `Content-Length`, `Content-Type`, or HMAC headers are
  rejected to avoid proxy/container interpretation differences.
- Request bodies are cached before canonicalization so downstream handlers can
  read the original bytes. The default pre-authentication limit is 1 MiB.
- Unknown, disabled, expired, or revoked credentials resolve to the same
  `INVALID_CREDENTIAL` response, avoiding AppKey enumeration.

## Flow

1. Validate unique and required headers, signature version, timestamp format
   and request size.
2. Read and cache the raw request body.
3. Resolve a defensive copy of the active Secret.
4. Canonicalize the request using `HmacCanonicalizer`.
5. Reject timestamps outside the inclusive `±300s` window.
6. Recompute HMAC-SHA256 and compare with `MessageDigest.isEqual`.
7. Atomically claim the app/nonce pair in Redis with `SET NX PX`.
8. Attach the authenticated AppKey and request ID to the wrapped request, then
   pass it to authorization, rate limiting and routing.

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
| 413 | `REQUEST_TOO_LARGE` | false |
| 500 | `INTERNAL_CONFIGURATION`, `INTERNAL_ERROR` | false |
| 503 | `NONCE_STORE_UNAVAILABLE`, `CREDENTIAL_STORE_UNAVAILABLE` | true |

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

The application intentionally fails startup when no decryptor bean is present.
The current implementation has no Secret cache, so revocations and expiration
take effect on the next request. A bounded cache may be added later only with
credential/app epoch validation and a strict maximum staleness window.

## Remaining Production Work

- Implement and separately review the concrete KMS-backed
  `CredentialSecretDecryptor`; the runtime currently exposes only the tested
  integration port.
- Provision the gateway database role with `EXECUTE` on the lookup function and
  no unrestricted `BYPASSRLS` or broad tenant-table access.
- Add pre-authentication IP/connection rate limiting, bounded concurrency and
  route-specific body limits.
- Add application grant, API publication and tenant lifecycle authorization;
  the current resolver checks app/credential/tenant status only.
- Add route resolution, upstream proxy/orchestration dispatch, metering and
  sanitized request logging.
