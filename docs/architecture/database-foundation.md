# Database Foundation

## Scope

The Flyway migrations establish the MySQL-independent control-plane foundation
for:

- identity and tenancy;
- applications and credentials;
- API definitions, versions and production publications;
- upstream endpoint/environment registration;
- tenant orchestrations and immutable orchestration versions;
- idempotency records and the transactional outbox.

`V1__foundation.sql` creates the schema and invariants.
`V2__active_credential_lookup.sql` adds the constrained gateway authentication
lookup function.
`V3__api_authorization_lookup.sql` adds application/grant authorization.
`V4__post_auth_limits_and_policies.sql` adds application/API rate and quota
policies, returns `app_id` from authorization and adds the restricted policy
lookup function. `V5__route_templates_and_proxy_targets.sql` adds validated
route templates, ambiguity prevention and published upstream target lookup.

Runtime target: PostgreSQL 16+; integration tests run against embedded PostgreSQL 18.6.

## Tables

| Area | Tables |
| --- | --- |
| Identity | `iam_tenant`, `iam_user`, `iam_role_binding` |
| Applications | `app`, `app_credential`, `app_api_grant` |
| Upstreams | `upstream_endpoint`, `upstream_environment` |
| API catalogue | `api_definition`, `api_version`, `api_publication` |
| Orchestration | `orchestration`, `orchestration_version` |
| Reliability | `idempotency_record`, `outbox_event` |

## Database Invariants

- Tenant child tables carry `tenant_id` and use composite foreign keys such as `(tenant_id, app_id)`.
- RLS is enabled on tenant-owned tables; policies read `app.tenant_id` through `app_current_tenant_id()` and fail closed when it is absent.
- An app owner must already have a role binding in the same tenant.
- A publication must belong to the same API/version, be `PROD`, and use one of `PREPARED`, `ACTIVE`, `SUPERSEDED` or `REVOKED`.
- At most one publication per API/environment may be `ACTIVE`.
- `api_definition.active_prod_publication_id` is validated by a trigger and cannot reference a revoked or mismatched publication.
- A publication currently referenced by the active pointer cannot be changed to `REVOKED` or reparented.
- A deferred constraint trigger requires an active pointer to still reference an `ACTIVE` publication at transaction commit.
- Immutable API/orchestration versions are represented by separate rows; later service-layer code must reject in-place business updates.

## Gateway Credential Lookup

`auth_resolve_active_credential(TEXT)` is a `SECURITY DEFINER` function that
allows the public gateway to resolve an AppKey before a tenant context exists.
The function:

- uses `SET search_path = pg_catalog, public`;
- returns only credential, KMS key, ciphertext and auth-epoch metadata;
- accepts credential status `ACTIVE` or unexpired overlap `ROTATING`;
- requires the app and tenant to remain `ACTIVE`;
- rejects expired credentials;
- revokes execution from `PUBLIC`.

Production provisioning must create the gateway database role outside Flyway
and grant `EXECUTE` on this function. The role should not receive unrestricted
tenant-table access or `BYPASSRLS`.

## API Authorization Lookup

`auth_authorize_public_api(appKey, method, path)` is also a `SECURITY DEFINER`
function with a fixed `search_path`. It:

- revalidates the ACTIVE credential, app and tenant;
- resolves an exact or templated route whose `active_prod_publication_id`
  references an ACTIVE PROD publication;
- gives literal segments precedence over parameter segments;
- returns a validated route-parameter JSON object;
- allows `PLATFORM_PUBLIC` across tenants but requires `TENANT_PRIVATE` API
  ownership to match the credential tenant;
- requires an ACTIVE `app_api_grant`;
- returns stable decisions `ALLOWED`, `API_NOT_FOUND`, `API_NOT_GRANTED` or
  `INVALID_CREDENTIAL`;
- returns `app_id` on `ALLOWED` so post-auth counters are application-wide
  across credential rotation;
- revokes execution from `PUBLIC`.

Route templates use literal safe segments or `{name}` placeholders. Duplicate
parameter names are rejected. `route_signature` replaces parameter names with
`{}` and a unique index on `(public_method, route_signature)` prevents
ambiguous route shapes.

Gateway startup verifies `EXECUTE` on `auth_resolve_active_credential`,
`auth_authorize_public_api`, `auth_resolve_post_auth_policies` and
`auth_resolve_api_target`, rejects superuser/BYPASSRLS roles, and verifies the
role has no direct `app_credential` DML privileges.

## Post-Auth Policy Lookup

`rate_limit_policy` stores one `TOKEN_BUCKET` rule per `TENANT`, `APP` or `API`
scope. `quota_policy` stores independent `DAY`/`MONTH` `CALLS` limits. Both
tables:

- enable RLS;
- isolate tenant-owned rows with `app_current_tenant_id()`;
- keep API-scope rows global with `tenant_id IS NULL`;
- use unique scope keys so one scope cannot resolve to ambiguous rows.

The current runtime resolves `APP` and `API` scopes. `TENANT` scope is schema
groundwork and is not yet included in the post-auth decision.

`auth_resolve_post_auth_policies(appId, apiId)` is `SECURITY DEFINER` with a
fixed `search_path`. Application policy rows must match the application's
actual `tenant_id`; mismatched rows are ignored. API policy rows must be
platform-global. The function returns one row of nullable overrides, allowing
the runtime to apply mandatory process defaults where no row exists.

The gateway role receives `EXECUTE` only. It does not receive direct policy
table access.

## Published Upstream Target Lookup

`auth_resolve_api_target(apiId, apiVersionId)` is `SECURITY DEFINER` with a
fixed `search_path`. It returns upstream method, path template, HTTPS base URL
and timeout only when:

- the API is PUBLISHED and kind `PROXY`;
- the active PROD publication matches the requested version;
- the API version is PUBLISHED;
- the configured endpoint belongs to the API owner and is ACTIVE;
- the newest ACTIVE PROD environment is selected.

Malformed JSON endpoint IDs do not resolve. The runtime role receives
`EXECUTE` and no direct upstream table access.

## Test Command

```bash
mvn -pl platform-persistence test
```

The tests use native embedded PostgreSQL, run Flyway, assume a non-superuser runtime role, and verify:

- all foundation tables exist;
- RLS is enabled on all tenant tables;
- cross-tenant composite keys are rejected;
- tenant rows are filtered and cross-tenant inserts are rejected;
- non-PROD publication insertion is rejected;
- one-active-publication-per-API is enforced;
- active pointers cannot reference revoked publications;
- an active publication cannot be revoked while still referenced by the active pointer.
- a superseded publication cannot remain referenced by the active pointer at commit.
- active credentials resolve without a tenant GUC through the restricted function;
- rotating, suspended, revoked and expired credential paths fail closed.
- exact published routes with ACTIVE grants return ALLOWED;
- missing/revoked grants, private cross-tenant APIs and credential races fail
  with stable decisions.
- application/API policy overrides resolve through the restricted function;
- policy tables enforce RLS and unique scope resolution;
- application policy rows owned by another tenant are ignored.
- literal route segments win over parameter segments;
- duplicate parameter names and ambiguous route shapes are rejected;
- safe route parameters are extracted and unsafe encoded separators do not
  match;
- only the active published proxy version resolves an ACTIVE PROD target.

## Out Of Scope

- usage/request/audit partition tables;
- JPA mappings;
- production role provisioning and grants;
- schema partitioning and retention jobs;
- migration rollback scripts.

Production deployment must create the runtime/login roles outside Flyway and
grant only the required function and schema/table privileges.
