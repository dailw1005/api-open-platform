CREATE OR REPLACE FUNCTION auth_authorize_public_api(
    p_app_key TEXT,
    p_method TEXT,
    p_path TEXT
)
RETURNS TABLE (
    decision TEXT,
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
            NULL::VARCHAR(24);
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'ALLOWED'::TEXT,
        v_api_id,
        v_api_version_id,
        v_tenant_id,
        v_visibility;
END;
$$;

REVOKE ALL
    ON FUNCTION auth_authorize_public_api(TEXT, TEXT, TEXT)
    FROM PUBLIC;
