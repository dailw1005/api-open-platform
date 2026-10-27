package com.apiproject.control.iam;

import java.util.Objects;

public record AdminLoginIdentity(
        AdminIdentity identity,
        String passwordHash,
        boolean mfaEnabled
) {

    public AdminLoginIdentity {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(passwordHash, "passwordHash");
    }
}
