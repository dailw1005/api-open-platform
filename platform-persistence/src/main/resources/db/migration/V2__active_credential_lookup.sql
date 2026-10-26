CREATE OR REPLACE FUNCTION auth_resolve_active_credential(p_app_key TEXT)
RETURNS TABLE (
    credential_id UUID,
    tenant_id UUID,
    app_id UUID,
    kms_key_id VARCHAR(200),
    secret_ciphertext BYTEA,
    app_auth_epoch BIGINT,
    credential_auth_epoch BIGINT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        credential.id,
        credential.tenant_id,
        credential.app_id,
        credential.kms_key_id,
        credential.secret_ciphertext,
        app.auth_epoch,
        credential.auth_epoch
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
      )
$$;

REVOKE ALL
    ON FUNCTION auth_resolve_active_credential(TEXT)
    FROM PUBLIC;
