package com.apiproject.gateway.security;

import java.util.Objects;

public final class ApiTargetResolutionException extends RuntimeException {

    private final String code;
    private final boolean retryable;

    public ApiTargetResolutionException(
            String code,
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        if (!"UPSTREAM_CONFIGURATION_ERROR".equals(code) || retryable) {
            throw new IllegalArgumentException(
                    "unsupported target resolution error mapping"
            );
        }
        this.code = code;
        this.retryable = false;
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
