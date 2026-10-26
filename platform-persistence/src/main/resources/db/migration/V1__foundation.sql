CREATE TABLE iam_tenant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE iam_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE iam_role_binding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    user_id UUID NOT NULL REFERENCES iam_user(id),
    role_code VARCHAR(32) NOT NULL
        CHECK (role_code IN ('PLATFORM_ADMIN', 'APP_DEVELOPER', 'VIEWER')),
    scope_type VARCHAR(16) NOT NULL DEFAULT 'TENANT'
        CHECK (scope_type IN ('GLOBAL', 'TENANT')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

CREATE TABLE app (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    name VARCHAR(100) NOT NULL,
    owner_user_id UUID NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    description VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    FOREIGN KEY (tenant_id, owner_user_id)
        REFERENCES iam_role_binding(tenant_id, user_id)
);

CREATE TABLE app_credential (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    app_id UUID NOT NULL,
    app_key VARCHAR(128) NOT NULL UNIQUE,
    secret_ciphertext BYTEA NOT NULL,
    kms_key_id VARCHAR(200) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'ROTATING', 'REVOKED', 'EXPIRED')),
    auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, app_id) REFERENCES app(tenant_id, id)
);

CREATE TABLE app_api_grant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    app_id UUID NOT NULL,
    api_id UUID NOT NULL,
    granted_by UUID NOT NULL REFERENCES iam_user(id),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'REVOKED')),
    auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id, api_id),
    FOREIGN KEY (tenant_id, app_id) REFERENCES app(tenant_id, id)
);

CREATE TABLE upstream_endpoint (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    code VARCHAR(64) NOT NULL,
    name VARCHAR(120) NOT NULL,
    method VARCHAR(8) NOT NULL
        CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    path_template VARCHAR(1000) NOT NULL CHECK (path_template LIKE '/%'),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'OFFLINE')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_tenant_id, id),
    UNIQUE (owner_tenant_id, code)
);

CREATE TABLE upstream_environment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_tenant_id UUID NOT NULL,
    endpoint_id UUID NOT NULL,
    environment VARCHAR(16) NOT NULL
        CHECK (environment IN ('PROD', 'SANDBOX')),
    version INTEGER NOT NULL CHECK (version > 0),
    base_url TEXT NOT NULL CHECK (base_url LIKE 'https://%'),
    auth_ref VARCHAR(200),
    egress_zone VARCHAR(64) NOT NULL,
    tls_policy VARCHAR(32) NOT NULL
        CHECK (tls_policy IN ('TLS_1_2_STRICT', 'TLS_1_3_STRICT')),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'OFFLINE')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, environment, version),
    FOREIGN KEY (owner_tenant_id, endpoint_id)
        REFERENCES upstream_endpoint(owner_tenant_id, id)
);

CREATE TABLE api_definition (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    code VARCHAR(64) NOT NULL,
    name VARCHAR(120) NOT NULL,
    public_method VARCHAR(8) NOT NULL
        CHECK (public_method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    public_path VARCHAR(1000) NOT NULL,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('PROXY', 'ORCHESTRATION')),
    visibility VARCHAR(24) NOT NULL
        CHECK (visibility IN ('PLATFORM_PUBLIC', 'TENANT_PRIVATE')),
    active_prod_publication_id UUID,
    status VARCHAR(16) NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT', 'IN_REVIEW', 'PUBLISHED', 'DEPRECATED', 'OFFLINE')),
    publish_epoch BIGINT NOT NULL DEFAULT 1 CHECK (publish_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (public_method, public_path),
    UNIQUE (owner_tenant_id, code)
);

CREATE TABLE api_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id UUID NOT NULL REFERENCES api_definition(id),
    version INTEGER NOT NULL CHECK (version > 0),
    status VARCHAR(16) NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT', 'PUBLISHED', 'DEPRECATED', 'OFFLINE')),
    request_schema JSONB NOT NULL,
    response_schema JSONB NOT NULL,
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1 AND 30000),
    config_json JSONB NOT NULL,
    config_checksum CHAR(64) NOT NULL,
    created_by UUID NOT NULL REFERENCES iam_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (api_id, id),
    UNIQUE (api_id, version)
);

CREATE TABLE api_publication (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id UUID NOT NULL REFERENCES api_definition(id),
    owner_tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    visibility VARCHAR(24) NOT NULL
        CHECK (visibility IN ('PLATFORM_PUBLIC', 'TENANT_PRIVATE')),
    api_version_id UUID NOT NULL,
    environment VARCHAR(16) NOT NULL CHECK (environment = 'PROD'),
    publication_no BIGINT NOT NULL CHECK (publication_no > 0),
    status VARCHAR(16) NOT NULL
        CHECK (status IN ('PREPARED', 'ACTIVE', 'SUPERSEDED', 'REVOKED')),
    manifest_json JSONB NOT NULL,
    manifest_checksum CHAR(64) NOT NULL,
    previous_publication_id UUID REFERENCES api_publication(id),
    published_by UUID NOT NULL REFERENCES iam_user(id),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (api_id, environment, publication_no),
    FOREIGN KEY (api_id, api_version_id) REFERENCES api_version(api_id, id)
);

CREATE UNIQUE INDEX uq_api_publication_single_active
    ON api_publication (api_id, environment)
    WHERE status = 'ACTIVE';

ALTER TABLE api_definition
    ADD CONSTRAINT fk_api_definition_active_prod_publication
    FOREIGN KEY (active_prod_publication_id)
    REFERENCES api_publication(id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE app_api_grant
    ADD CONSTRAINT fk_app_api_grant_api
    FOREIGN KEY (api_id) REFERENCES api_definition(id);

CREATE TABLE orchestration (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    code VARCHAR(64) NOT NULL,
    name VARCHAR(120) NOT NULL,
    owner_user_id UUID NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT', 'VALIDATED', 'IN_REVIEW', 'PUBLISHED', 'DEPRECATED', 'ARCHIVED')),
    latest_published_version_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, code),
    FOREIGN KEY (tenant_id, owner_user_id)
        REFERENCES iam_role_binding(tenant_id, user_id)
);

CREATE TABLE orchestration_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    orchestration_id UUID NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    dsl_json JSONB NOT NULL,
    compiled_ir_json JSONB NOT NULL,
    required_api_set_json JSONB NOT NULL,
    checksum CHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL
        CHECK (status IN ('DRAFT', 'VALIDATED', 'IN_REVIEW', 'PUBLISHED', 'DEPRECATED', 'ARCHIVED')),
    created_by UUID NOT NULL REFERENCES iam_user(id),
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, orchestration_id, version),
    FOREIGN KEY (tenant_id, orchestration_id)
        REFERENCES orchestration(tenant_id, id)
);

CREATE TABLE idempotency_record (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    app_id UUID NOT NULL,
    scope VARCHAR(24) NOT NULL CHECK (scope IN ('PUBLIC_ROOT', 'FLOW_NODE', 'TEST_RUN')),
    root_request_id UUID NOT NULL,
    node_id VARCHAR(64),
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL
        CHECK (state IN ('RESERVED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'EXPIRED')),
    dispatch_state VARCHAR(24) NOT NULL
        CHECK (dispatch_state IN ('NOT_DISPATCHED', 'POSSIBLY_DISPATCHED')),
    lease_until TIMESTAMPTZ,
    response_status INTEGER,
    response_ref TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id, scope, idempotency_key),
    FOREIGN KEY (tenant_id, app_id) REFERENCES app(tenant_id, id)
);

CREATE TABLE outbox_event (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES iam_tenant(id),
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_app_tenant_created
    ON app (tenant_id, created_at DESC);
CREATE INDEX idx_app_credential_app
    ON app_credential (tenant_id, app_id);
CREATE INDEX idx_app_api_grant_app
    ON app_api_grant (tenant_id, app_id);
CREATE INDEX idx_orchestration_tenant_updated
    ON orchestration (tenant_id, updated_at DESC);
CREATE INDEX idx_orchestration_version_orchestration
    ON orchestration_version (tenant_id, orchestration_id);
CREATE INDEX idx_idempotency_expiry
    ON idempotency_record (expires_at);
CREATE INDEX idx_outbox_pending
    ON outbox_event (status, available_at)
    WHERE status IN ('PENDING', 'FAILED');

CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS UUID
LANGUAGE SQL
STABLE
AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

ALTER TABLE iam_tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_role_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE app ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_api_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestration ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestration_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_event ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_self_isolation ON iam_tenant
    USING (id = app_current_tenant_id())
    WITH CHECK (id = app_current_tenant_id());

CREATE POLICY tenant_role_isolation ON iam_role_binding
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_app_isolation ON app
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_credential_isolation ON app_credential
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_grant_isolation ON app_api_grant
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_orchestration_isolation ON orchestration
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_orchestration_version_isolation ON orchestration_version
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_idempotency_isolation ON idempotency_record
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_outbox_isolation ON outbox_event
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE OR REPLACE FUNCTION enforce_active_publication_pointer()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    publication api_publication%ROWTYPE;
BEGIN
    IF NEW.active_prod_publication_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT *
    INTO publication
    FROM api_publication
    WHERE id = NEW.active_prod_publication_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'active publication does not exist'
            USING ERRCODE = '23514';
    END IF;

    IF publication.api_id <> NEW.id
        OR publication.owner_tenant_id <> NEW.owner_tenant_id
        OR publication.visibility <> NEW.visibility
        OR publication.environment <> 'PROD'
        OR publication.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'active publication violates API guard'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_api_definition_active_publication_guard
BEFORE INSERT OR UPDATE OF active_prod_publication_id
ON api_definition
FOR EACH ROW
EXECUTE FUNCTION enforce_active_publication_pointer();
