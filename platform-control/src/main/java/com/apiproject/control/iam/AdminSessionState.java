package com.apiproject.control.iam;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record AdminSessionState(
        UUID userId,
        String csrfTokenHash,
        Instant expiresAt
) {

    public AdminSessionState {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(csrfTokenHash, "csrfTokenHash");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
