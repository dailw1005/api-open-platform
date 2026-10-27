package com.apiproject.control.iam;

import java.util.Objects;

public record AdminSession(
        String tokenHash,
        AdminSessionState state
) {

    public AdminSession {
        Objects.requireNonNull(tokenHash, "tokenHash");
        Objects.requireNonNull(state, "state");
    }
}
