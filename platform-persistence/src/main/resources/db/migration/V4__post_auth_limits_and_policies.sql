CREATE TABLE rate_limit_policy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES iam_tenant(id),
    scope_type VARCHAR(16) NOT NULL
        CHECK (scope_type IN ('TENANT', 'APP', 'API')),
    scope_id UUID NOT NULL,
    limit_value BIGINT NOT NULL CHECK (limit_value > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    burst INTEGER NOT NULL CHECK (burst > 0),
    algorithm VARCHAR(32) NOT NULL
        CHECK (algorithm = 'TOKEN_BUCKET'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (scope_type = 'TENANT' AND tenant_id IS NOT NULL
            AND scope_id = tenant_id)
        OR (scope_type = 'APP' AND tenant_id IS NOT NULL)
        OR (scope_type = 'API' AND tenant_id IS NULL)
    )
);

CREATE UNIQUE INDEX uq_rate_limit_policy_scope_algorithm
    ON rate_limit_policy (scope_type, scope_id, algorithm);

CREATE INDEX idx_rate_limit_policy_lookup
    ON rate_limit_policy (scope_type, scope_id)
    WHERE enabled;

CREATE TABLE quota_policy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES iam_tenant(id),
    scope_type VARCHAR(16) NOT NULL
        CHECK (scope_type IN ('TENANT', 'APP', 'API')),
    scope_id UUID NOT NULL,
    period VARCHAR(16) NOT NULL CHECK (period IN ('DAY', 'MONTH')),
    limit_value BIGINT NOT NULL CHECK (limit_value > 0),
    metric VARCHAR(24) NOT NULL CHECK (metric = 'CALLS'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (scope_type = 'TENANT' AND tenant_id IS NOT NULL
            AND scope_id = tenant_id)
        OR (scope_type = 'APP' AND tenant_id IS NOT NULL)
        OR (scope_type = 'API' AND tenant_id IS NULL)
    )
);

CREATE UNIQUE INDEX uq_quota_policy_scope_period_metric
    ON quota_policy (scope_type, scope_id, period, metric);

CREATE INDEX idx_quota_policy_lookup
    ON quota_policy (scope_type, scope_id)
    WHERE enabled;

ALTER TABLE rate_limit_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_policy ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_rate_limit_policy_isolation ON rate_limit_policy
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY tenant_quota_policy_isolation ON quota_policy
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

DROP FUNCTION auth_authorize_public_api(TEXT, TEXT, TEXT);

CREATE FUNCTION auth_authorize_public_api(
    p_app_key TEXT,
    p_method TEXT,
    p_path TEXT
)
RETURNS TABLE (
    decision TEXT,
    app_id UUID,
    api_id UUID,
    api_version_id UUID,
    tenant_id UUID,
    visibility VARCHAR(24)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_tenant_id UUID;
    v_app_id UUID;
    v_api_id UUID;
    v_api_version_id UUID;
    v_visibility VARCHAR(24);
BEGIN
    SELECT credential.tenant_id, credential.app_id
    INTO v_tenant_id, v_app_id
    FROM public.app_credential AS credential
    JOIN public.app AS app
      ON app.tenant_id = credential.tenant_id
     AND app.id = credential.app_id
    JOIN public.iam_tenant AS tenant
      ON tenant.id = credential.tenant_id
    WHERE credential.app_key = p_app_key
      AND credential.status IN ('ACTIVE', 'ROTATING')
      AND app.status = 'ACTIVE'
      AND tenant.status = 'ACTIVE'
      AND (
          credential.expires_at IS NULL
          OR credential.expires_at > now()
      );

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'INVALID_CREDENTIAL'::TEXT,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::VARCHAR(24);
        RETURN;
    END IF;

    SELECT api.id, publication.api_version_id, api.visibility
    INTO v_api_id, v_api_version_id, v_visibility
    FROM public.api_definition AS api
    JOIN public.api_publication AS publication
      ON publication.id = api.active_prod_publication_id
    WHERE api.public_method = upper(p_method)
      AND api.public_path = p_path
      AND api.status = 'PUBLISHED'
      AND publication.api_id = api.id
      AND publication.owner_tenant_id = api.owner_tenant_id
      AND publication.visibility = api.visibility
      AND publication.environment = 'PROD'
      AND publication.status = 'ACTIVE'
      AND (
          api.visibility = 'PLATFORM_PUBLIC'
          OR api.owner_tenant_id = v_tenant_id
      );

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'API_NOT_FOUND'::TEXT,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::VARCHAR(24);
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.app_api_grant AS grant_record
        WHERE grant_record.tenant_id = v_tenant_id
          AND grant_record.app_id = v_app_id
          AND grant_record.api_id = v_api_id
          AND grant_record.status = 'ACTIVE'
    ) THEN
        RETURN QUERY SELECT
            'API_NOT_GRANTED'::TEXT,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::VARCHAR(24);
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'ALLOWED'::TEXT,
        v_app_id,
        v_api_id,
        v_api_version_id,
        v_tenant_id,
        v_visibility;
END;
$$;

REVOKE ALL
    ON FUNCTION auth_authorize_public_api(TEXT, TEXT, TEXT)
    FROM PUBLIC;

CREATE FUNCTION auth_resolve_post_auth_policies(
    p_app_id UUID,
    p_api_id UUID
)
RETURNS TABLE (
    app_rate_requests BIGINT,
    app_rate_window_seconds INTEGER,
    app_rate_burst INTEGER,
    api_rate_requests BIGINT,
    api_rate_window_seconds INTEGER,
    api_rate_burst INTEGER,
    app_daily_quota BIGINT,
    app_monthly_quota BIGINT,
    api_daily_quota BIGINT,
    api_monthly_quota BIGINT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH
    app_rate AS (
        SELECT policy.limit_value, policy.window_seconds, policy.burst
        FROM public.rate_limit_policy AS policy
        JOIN public.app
          ON app.id = p_app_id
         AND app.tenant_id = policy.tenant_id
        WHERE policy.scope_type = 'APP'
          AND policy.scope_id = p_app_id
          AND policy.algorithm = 'TOKEN_BUCKET'
          AND policy.enabled
    ),
    api_rate AS (
        SELECT policy.limit_value, policy.window_seconds, policy.burst
        FROM public.rate_limit_policy AS policy
        WHERE policy.scope_type = 'API'
          AND policy.scope_id = p_api_id
          AND policy.tenant_id IS NULL
          AND policy.algorithm = 'TOKEN_BUCKET'
          AND policy.enabled
    ),
    app_daily AS (
        SELECT policy.limit_value
        FROM public.quota_policy AS policy
        JOIN public.app
          ON app.id = p_app_id
         AND app.tenant_id = policy.tenant_id
        WHERE policy.scope_type = 'APP'
          AND policy.scope_id = p_app_id
          AND policy.period = 'DAY'
          AND policy.metric = 'CALLS'
          AND policy.enabled
    ),
    app_monthly AS (
        SELECT policy.limit_value
        FROM public.quota_policy AS policy
        JOIN public.app
          ON app.id = p_app_id
         AND app.tenant_id = policy.tenant_id
        WHERE policy.scope_type = 'APP'
          AND policy.scope_id = p_app_id
          AND policy.period = 'MONTH'
          AND policy.metric = 'CALLS'
          AND policy.enabled
    ),
    api_daily AS (
        SELECT policy.limit_value
        FROM public.quota_policy AS policy
        WHERE policy.scope_type = 'API'
          AND policy.scope_id = p_api_id
          AND policy.tenant_id IS NULL
          AND policy.period = 'DAY'
          AND policy.metric = 'CALLS'
          AND policy.enabled
    ),
    api_monthly AS (
        SELECT policy.limit_value
        FROM public.quota_policy AS policy
        WHERE policy.scope_type = 'API'
          AND policy.scope_id = p_api_id
          AND policy.tenant_id IS NULL
          AND policy.period = 'MONTH'
          AND policy.metric = 'CALLS'
          AND policy.enabled
    )
    SELECT
        (SELECT limit_value FROM app_rate),
        (SELECT window_seconds FROM app_rate),
        (SELECT burst FROM app_rate),
        (SELECT limit_value FROM api_rate),
        (SELECT window_seconds FROM api_rate),
        (SELECT burst FROM api_rate),
        (SELECT limit_value FROM app_daily),
        (SELECT limit_value FROM app_monthly),
        (SELECT limit_value FROM api_daily),
        (SELECT limit_value FROM api_monthly)
$$;

REVOKE ALL
    ON FUNCTION auth_resolve_post_auth_policies(UUID, UUID)
    FROM PUBLIC;
