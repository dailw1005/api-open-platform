package com.apiproject.control.iam;

import java.time.Instant;
import java.util.Objects;

public record AdminSessionTokens(
        String sessionToken,
        String csrfToken,
        AdminIdentity identity,
        Instant expiresAt
) {

    public AdminSessionTokens {
        Objects.requireNonNull(sessionToken, "sessionToken");
        Objects.requireNonNull(csrfToken, "csrfToken");
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
