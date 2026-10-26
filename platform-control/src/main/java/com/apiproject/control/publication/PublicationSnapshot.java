package com.apiproject.control.publication;

import java.util.Objects;

public record PublicationSnapshot(
        String id,
        String apiId,
        String ownerTenantId,
        Visibility visibility,
        PublicationEnvironment environment,
        PublicationStatus status
) {
    public PublicationSnapshot {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(apiId, "apiId");
        Objects.requireNonNull(ownerTenantId, "ownerTenantId");
        Objects.requireNonNull(visibility, "visibility");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(status, "status");
    }
}
