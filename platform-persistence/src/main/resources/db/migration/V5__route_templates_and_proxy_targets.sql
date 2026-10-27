CREATE OR REPLACE FUNCTION is_valid_public_route_template(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    segment TEXT;
    parameter_name TEXT;
    seen_parameters TEXT[] := ARRAY[]::TEXT[];
BEGIN
    IF candidate !~ '^/' OR candidate ~ '//' THEN
        RETURN FALSE;
    END IF;
    IF candidate <> '/' AND candidate ~ '/$' THEN
        RETURN FALSE;
    END IF;

    FOREACH segment IN ARRAY string_to_array(candidate, '/')
    LOOP
        CONTINUE WHEN segment = '';

        IF segment ~ '^\{[A-Za-z][A-Za-z0-9_]{0,63}\}$' THEN
            parameter_name := substring(
                segment
                FROM 2
                FOR length(segment) - 2
            );
            IF parameter_name = ANY (seen_parameters) THEN
                RETURN FALSE;
            END IF;
            seen_parameters := array_append(
                seen_parameters,
                parameter_name
            );
        ELSIF segment !~ '^[A-Za-z0-9._~-]+$' THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$;

ALTER TABLE api_definition
    ADD CONSTRAINT chk_api_definition_public_route_template
    CHECK (is_valid_public_route_template(public_path));

ALTER TABLE upstream_endpoint
    ADD CONSTRAINT chk_upstream_endpoint_route_template
    CHECK (is_valid_public_route_template(path_template));

ALTER TABLE api_definition
    ADD COLUMN route_signature VARCHAR(1000)
    GENERATED ALWAYS AS (
        regexp_replace(
            public_path,
            '\{[A-Za-z][A-Za-z0-9_]{0,63}\}',
            '{}',
            'g'
        )
    ) STORED;

CREATE UNIQUE INDEX uq_api_definition_method_route_signature
    ON api_definition (public_method, route_signature);

CREATE FUNCTION auth_match_public_route(
    p_method TEXT,
    p_path TEXT
)
RETURNS TABLE (
    api_id UUID,
    api_version_id UUID,
    owner_tenant_id UUID,
    visibility VARCHAR(24),
    route_params JSONB
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH candidates AS (
        SELECT
            api.id AS api_id,
            publication.api_version_id,
            api.owner_tenant_id,
            api.visibility,
            api.public_path,
            (
                SELECT string_agg(
                    CASE
                        WHEN part.segment ~
                            '^\{[A-Za-z][A-Za-z0-9_]{0,63}\}$'
                        THEN '0'
                        ELSE '1'
                    END,
                    ''
                    ORDER BY part.position
                )
                FROM unnest(
                    string_to_array(api.public_path, '/')
                ) WITH ORDINALITY AS part(segment, position)
            ) AS literal_mask
        FROM public.api_definition AS api
        JOIN public.api_publication AS publication
          ON publication.id = api.active_prod_publication_id
        WHERE api.public_method = upper(p_method)
          AND api.status = 'PUBLISHED'
          AND publication.api_id = api.id
          AND publication.owner_tenant_id = api.owner_tenant_id
          AND publication.visibility = api.visibility
          AND publication.environment = 'PROD'
          AND publication.status = 'ACTIVE'
          AND cardinality(string_to_array(api.public_path, '/'))
              = cardinality(string_to_array(p_path, '/'))
          AND NOT EXISTS (
              SELECT 1
              FROM unnest(
                  string_to_array(api.public_path, '/')
              ) WITH ORDINALITY AS part(segment, position)
              WHERE (
                  part.segment ~
                      '^\{[A-Za-z][A-Za-z0-9_]{0,63}\}$'
                  AND split_part(p_path, '/', part.position::INTEGER)
                      !~ '^[A-Za-z0-9._~-]+$'
              )
              OR (
                  part.segment !~
                      '^\{[A-Za-z][A-Za-z0-9_]{0,63}\}$'
                  AND part.segment
                      <> split_part(
                          p_path,
                          '/',
                          part.position::INTEGER
                      )
              )
          )
    )
    SELECT
        candidates.api_id,
        candidates.api_version_id,
        candidates.owner_tenant_id,
        candidates.visibility,
        COALESCE(
            (
                SELECT jsonb_object_agg(
                    substring(
                        part.segment
                        FROM 2
                        FOR length(part.segment) - 2
                    ),
                    split_part(p_path, '/', part.position::INTEGER)
                )
                FROM unnest(
                    string_to_array(candidates.public_path, '/')
                ) WITH ORDINALITY AS part(segment, position)
                WHERE part.segment ~
                    '^\{[A-Za-z][A-Za-z0-9_]{0,63}\}$'
            ),
            '{}'::JSONB
        )
    FROM candidates
    ORDER BY candidates.literal_mask DESC, candidates.public_path ASC
    LIMIT 1
$$;

REVOKE ALL
    ON FUNCTION auth_match_public_route(TEXT, TEXT)
    FROM PUBLIC;

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
    visibility VARCHAR(24),
    route_params JSONB
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
    v_route_params JSONB;
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
            NULL::VARCHAR(24),
            NULL::JSONB;
        RETURN;
    END IF;

    SELECT
        route.api_id,
        route.api_version_id,
        route.visibility,
        route.route_params
    INTO
        v_api_id,
        v_api_version_id,
        v_visibility,
        v_route_params
    FROM auth_match_public_route(p_method, p_path) AS route
    WHERE route.visibility = 'PLATFORM_PUBLIC'
       OR route.owner_tenant_id = v_tenant_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'API_NOT_FOUND'::TEXT,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::VARCHAR(24),
            NULL::JSONB;
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
            NULL::VARCHAR(24),
            NULL::JSONB;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'ALLOWED'::TEXT,
        v_app_id,
        v_api_id,
        v_api_version_id,
        v_tenant_id,
        v_visibility,
        COALESCE(v_route_params, '{}'::JSONB);
END;
$$;

REVOKE ALL
    ON FUNCTION auth_authorize_public_api(TEXT, TEXT, TEXT)
    FROM PUBLIC;

CREATE FUNCTION auth_resolve_api_target(
    p_api_id UUID,
    p_api_version_id UUID
)
RETURNS TABLE (
    upstream_method VARCHAR(8),
    upstream_path_template VARCHAR(1000),
    base_url TEXT,
    timeout_ms INTEGER
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        endpoint.method,
        endpoint.path_template,
        environment.base_url,
        version.timeout_ms
    FROM public.api_definition AS api
    JOIN public.api_publication AS publication
      ON publication.id = api.active_prod_publication_id
    JOIN public.api_version AS version
      ON version.id = publication.api_version_id
     AND version.api_id = api.id
    JOIN public.upstream_endpoint AS endpoint
      ON endpoint.owner_tenant_id = api.owner_tenant_id
     AND endpoint.id = CASE
         WHEN version.config_json->>'upstreamEndpointId'
             ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
         THEN (version.config_json->>'upstreamEndpointId')::UUID
         ELSE NULL::UUID
     END
    JOIN LATERAL (
        SELECT candidate.base_url
        FROM public.upstream_environment AS candidate
        WHERE candidate.owner_tenant_id = api.owner_tenant_id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.environment = 'PROD'
          AND candidate.status = 'ACTIVE'
        ORDER BY candidate.version DESC
        LIMIT 1
    ) AS environment ON TRUE
    WHERE api.id = p_api_id
      AND api.kind = 'PROXY'
      AND api.status = 'PUBLISHED'
      AND publication.api_id = api.id
      AND publication.api_version_id = p_api_version_id
      AND publication.owner_tenant_id = api.owner_tenant_id
      AND publication.visibility = api.visibility
      AND publication.environment = 'PROD'
      AND publication.status = 'ACTIVE'
      AND version.status = 'PUBLISHED'
      AND endpoint.status = 'ACTIVE'
    LIMIT 1
$$;

REVOKE ALL
    ON FUNCTION auth_resolve_api_target(UUID, UUID)
    FROM PUBLIC;
