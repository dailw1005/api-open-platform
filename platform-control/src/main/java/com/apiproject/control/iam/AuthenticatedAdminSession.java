package com.apiproject.control.iam;

import java.util.Objects;

public record AuthenticatedAdminSession(
        AdminSessionState session,
        AdminIdentity identity
) {

    public AuthenticatedAdminSession {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(identity, "identity");
    }
}
