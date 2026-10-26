# Database Foundation

## Scope

The first Flyway migration (`V1__foundation.sql`) establishes the MySQL-independent control-plane foundation for:

- identity and tenancy;
- applications and credentials;
- API definitions, versions and production publications;
- upstream endpoint/environment registration;
- tenant orchestrations and immutable orchestration versions;
- idempotency records and the transactional outbox.

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

## Out Of Scope

- usage/request/audit partition tables;
- application repositories and JPA mappings;
- production role provisioning and grants;
- schema partitioning and retention jobs;
- migration rollback scripts.

Production deployment must create the runtime/login role outside Flyway and grant only the required schema/table privileges.
