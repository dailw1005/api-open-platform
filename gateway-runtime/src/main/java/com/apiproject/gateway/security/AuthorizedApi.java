package com.apiproject.gateway.security;

import java.util.Objects;
import java.util.UUID;

public record AuthorizedApi(
        UUID appId,
        UUID apiId,
        UUID apiVersionId,
        UUID tenantId,
        String visibility
) {

    public AuthorizedApi {
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(apiId, "apiId");
        Objects.requireNonNull(apiVersionId, "apiVersionId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(visibility, "visibility");
    }
}
