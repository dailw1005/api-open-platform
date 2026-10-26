package com.apiproject.gateway.security;

import java.util.Objects;

public final class PostAuthRateLimitException extends RuntimeException {

    private final String code;
    private final boolean retryable;

    public PostAuthRateLimitException(
            String code,
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        if ("RATE_LIMIT_UNAVAILABLE".equals(code) && retryable) {
            this.code = code;
        } else if ("INTERNAL_CONFIGURATION".equals(code) && !retryable) {
            this.code = code;
        } else {
            throw new IllegalArgumentException(
                    "unsupported post-auth rate limit error mapping"
            );
        }
        this.retryable = retryable;
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
