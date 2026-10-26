package com.apiproject.gateway.security;

import java.util.Objects;

public final class PreAuthRateLimitException extends RuntimeException {

    private final String code;
    private final boolean retryable;

    public PreAuthRateLimitException(
            String code,
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        if (!"RATE_LIMIT_UNAVAILABLE".equals(code) || !retryable) {
            throw new IllegalArgumentException("unsupported rate limit error mapping");
        }
        this.code = code;
        this.retryable = true;
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
