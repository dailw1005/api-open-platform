# Single API Proxy

## Scope

The first executable vertical slice turns an authenticated, authorized and
rate-limited public request into one HTTP request to a published upstream
endpoint. It supports:

- route templates with named path parameters;
- PROD target resolution from an immutable published API version;
- request body, query string and safe Header forwarding;
- bounded upstream timeout and response size;
- stable gateway errors for transport, timeout, server and configuration
  failures.

Orchestration dispatch, retries, upstream credential injection, usage events
and request logs remain later slices.

## Authorization Snapshot

`auth_authorize_public_api(appKey, method, path)` now returns:

```text
appId, apiId, apiVersionId, tenantId, visibility, routeParams
```

`routeParams` is a JSON object containing only validated path-parameter names
and values. It is carried in `AuthorizedApi` and is not accepted from the
client as structured input.

## Route Template Grammar

`api_definition.public_path` supports:

- literal segments using `A-Z`, `a-z`, `0-9`, `.`, `_`, `~` and `-`;
- named parameter segments such as `{userId}`;
- no query, fragment, backslash, double slash, trailing slash or dot segment;
- unique parameter names within one template;
- maximum stored length of 1000 characters.

Examples:

```text
/open/v1/orders/{orderId}
/open/v1/users/me
/open/v1/users/{userId}/history
```

Only one non-empty path segment may be captured by one parameter. Wildcards,
regular expressions and multi-segment captures are not supported.

## Resolution And Precedence

Only routes with an ACTIVE PROD publication are candidates. A request path is
split into segments and compared to each template:

- literal segments must match exactly;
- parameter segments accept one non-empty safe segment
  `[A-Za-z0-9._~-]+`;
- segment count must match exactly.

Literal segments win from left to right. For example:

```text
/users/me/{tab}
```

wins over:

```text
/users/{userId}/profile
```

for `/users/me/profile`.

`api_definition.route_signature` replaces parameter names with `{}`. A unique
index on `(public_method, route_signature)` rejects ambiguous route shapes such
as `/users/{id}` and `/users/{name}`.

Route resolution selects the most specific published route before checking
tenant visibility and application grant. It never falls back to a less
specific route when the selected route is private to another tenant or not
granted.

## Upstream Target Resolution

`auth_resolve_api_target(apiId, apiVersionId)` is `SECURITY DEFINER`, has a
fixed `search_path`, and is executable only by the gateway database role.

It requires:

- the API to be `PUBLISHED` and `PROXY`;
- the active publication to match the requested API version;
- the publication to remain ACTIVE PROD;
- the API version to be `PUBLISHED`;
- the configured upstream endpoint to be ACTIVE and owned by the API owner;
- an ACTIVE PROD upstream environment;
- the highest active environment version when more than one exists.

The returned target contains upstream method, path template, HTTPS base URL and
timeout. A missing target returns `TARGET_STORE_UNAVAILABLE` when the lookup
store fails, or `UPSTREAM_ERROR` when the configuration is invalid or absent.

## Proxy Execution

`HmacAuthenticationFilter` performs IP limiting, HMAC verification, Nonce claim,
route authorization and post-auth limits. `ApiProxyFilter` runs after it and
only processes requests carrying an `AuthorizedApi` snapshot.

The proxy:

- expands upstream path parameters from the authorization snapshot;
- appends the original raw query string;
- forwards only `Accept`, `Content-Type`, `Idempotency-Key`, `User-Agent` and
  `X-Client-Request-Id`;
- strips HMAC headers, cookies and hop-by-hop Headers;
- forwards at most 1 MiB of request body;
- does not follow upstream redirects;
- accepts upstream 2xx, 3xx and 4xx responses as upstream results;
- normalizes upstream 5xx responses to 502 `UPSTREAM_ERROR`;
- forwards only `Cache-Control`, `Content-Disposition`, `Content-Type`, `ETag`,
  `Last-Modified`, `Location` and `Retry-After` from upstream responses;
- adds the gateway-generated `X-Request-Id`;
- limits the buffered response to 1 MiB by default.

## Error Mapping

| Condition | HTTP | Code | Retryable |
| --- | --- | --- | --- |
| Missing authorized snapshot | 500 | `INTERNAL_CONFIGURATION` | false |
| Invalid route expansion or target | 502 | `UPSTREAM_ERROR` | false |
| Upstream transport failure | 502 | `UPSTREAM_ERROR` | true |
| Upstream 5xx | 502 | `UPSTREAM_ERROR` | true |
| Upstream timeout | 504 | `UPSTREAM_TIMEOUT` | true |
| Upstream response exceeds limit | 502 | `UPSTREAM_ERROR` | false |
| Target lookup store unavailable | 503 | `TARGET_STORE_UNAVAILABLE` | true |
| Oversized buffered request | 413 | `REQUEST_TOO_LARGE` | false |

Errors do not include upstream hostnames, IP addresses, exception messages or
response bodies from failed 5xx calls.

## SSRF Baseline

Targets must use HTTPS and must not contain user information, query, fragment,
backslash, dot segments or encoded path separators.

Literal `localhost`, loopback, unspecified, link-local, private, multicast,
carrier-grade NAT, documentation/reserved ranges and IPv6 unique-local
addresses are rejected. Redirect following is disabled.

DNS names are deliberately not resolved during target validation because a
second resolution by the HTTP client can create a rebinding gap. Production
must enforce an egress network policy or resolve-and-pin reviewed addresses.

## Known Gaps

- `upstream_environment.auth_ref` is not injected yet;
- upstream path parameters must use the same names as public route parameters;
- route-parameter segments must be unencoded safe characters; percent-encoded
  parameter values are canonicalized for HMAC but are not yet route-matched;
- DNS-backed private address rejection requires egress controls;
- response buffering is bounded but not streamed;
- no retry policy is applied to upstream transport failures;
- usage, request logs, pricing and audit events are not emitted yet;
- real staging upstream, TLS policy and egress zone validation are not executed.
