package com.apiproject.control.iam;

import java.util.Objects;
import java.util.Set;

public final class AdminAuthenticationException extends RuntimeException {

    private static final Set<String> NORMAL_CODES = Set.of(
            "INVALID_CREDENTIALS",
            "MFA_NOT_CONFIGURED",
            "SESSION_INVALID",
            "CSRF_INVALID",
            "INTERNAL_CONFIGURATION"
    );
    private static final Set<String> RETRYABLE_CODES = Set.of(
            "SESSION_STORE_UNAVAILABLE",
            "IDENTITY_STORE_UNAVAILABLE"
    );

    private final String code;
    private final boolean retryable;

    public AdminAuthenticationException(
            String code,
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        Objects.requireNonNull(code, "code");
        if (retryable && RETRYABLE_CODES.contains(code)) {
            this.code = code;
            this.retryable = true;
        } else if (!retryable && NORMAL_CODES.contains(code)) {
            this.code = code;
            this.retryable = false;
        } else {
            throw new IllegalArgumentException(
                    "unsupported admin authentication error mapping"
            );
        }
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
