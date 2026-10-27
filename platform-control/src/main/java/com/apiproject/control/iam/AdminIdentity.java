package com.apiproject.control.iam;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record AdminIdentity(
        UUID userId,
        String email,
        String displayName,
        List<SessionRoleBinding> roles
) {

    public AdminIdentity {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(roles, "roles");
        roles = List.copyOf(roles);
    }

    public boolean hasGlobalPlatformAdmin() {
        return roles.stream().anyMatch(role ->
                "PLATFORM_ADMIN".equals(role.roleCode())
                        && "GLOBAL".equals(role.scopeType())
        );
    }
}
