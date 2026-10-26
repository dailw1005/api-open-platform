package com.apiproject.app.security;

import java.util.Objects;
import java.util.UUID;

public record CredentialEncryptionContext(
        UUID tenantId,
        UUID appId,
        UUID credentialId,
        String appKey,
        String kmsKeyId
) {

    public CredentialEncryptionContext {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(appKey, "appKey");
        Objects.requireNonNull(kmsKeyId, "kmsKeyId");
    }
}
