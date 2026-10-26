# HMAC v1 Authentication

## Flow

1. Validate `X-Signature-Version` at the HTTP boundary.
2. Canonicalize the request using `HmacCanonicalizer`.
3. Reject timestamps outside the inclusive `±300s` window.
4. Recompute HMAC-SHA256 and compare with `MessageDigest.isEqual`.
5. Atomically claim the app/nonce pair in Redis with `SET NX PX`.
6. Only then pass the request to authorization, rate limiting and routing.

The nonce is deliberately claimed after signature verification so an unauthenticated caller cannot burn a valid client's nonce.

## Nonce Key

```text
apip:auth:nonce:v1:<sha256(appKey + NUL + nonce)>
```

- Hashing bounds key length and avoids exposing raw nonce values in operational tooling.
- Default TTL is `660s`: two 300-second timestamp windows plus 60 seconds of clock/network leeway.
- `SET NX PX` is a single atomic Redis command; concurrent attempts have exactly one winner.
- Redis errors fail closed. A request is not accepted if replay protection is unavailable.

## Redis Requirements

- Use an isolated Redis logical database or instance for nonce/security state.
- Set `maxmemory-policy noeviction`; evicting nonce keys would weaken replay protection.
- Enable authentication and TLS for non-local deployments.
- Apply connection and command timeouts; never retry a nonce claim blindly.
- Current implementation targets one Redis endpoint. Cluster/sentinel deployment is a later operational slice.

## Error Codes

| Code | Meaning |
| --- | --- |
| `INVALID_SIGNATURE_FORMAT` | Signature is not 64 lowercase hex characters |
| `TIMESTAMP_OUT_OF_WINDOW` | Request timestamp is outside the allowed skew |
| `INVALID_SIGNATURE` | Constant-time comparison failed |
| `INVALID_REQUEST` | Canonicalization rejected the request |
| `INTERNAL_CONFIGURATION` | Stored secret is invalid |
| `NONCE_REPLAYED` | Redis `SET NX PX` found an existing nonce |
| `NONCE_STORE_UNAVAILABLE` | Replay protection could not be consulted |

## Known Gap

The unit and Redis integration chain is complete, but it is not yet wired to the public HTTP filter. That integration must also attach request IDs, map codes to 400/401/503 responses and apply pre-auth rate limiting.
