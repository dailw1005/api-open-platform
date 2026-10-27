package com.apiproject.control.iam;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record SessionRoleBinding(
        UUID id,
        UUID userId,
        UUID tenantId,
        String roleCode,
        String scopeType
) {

    private static final Set<String> ROLE_CODES = Set.of(
            "PLATFORM_ADMIN",
            "APP_DEVELOPER",
            "VIEWER"
    );
    private static final Set<String> SCOPE_TYPES = Set.of("GLOBAL", "TENANT");

    public SessionRoleBinding {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(userId, "userId");
        if (!ROLE_CODES.contains(roleCode)) {
            throw new IllegalArgumentException("roleCode is invalid");
        }
        if (!SCOPE_TYPES.contains(scopeType)) {
            throw new IllegalArgumentException("scopeType is invalid");
        }
    }
}
