package com.apiproject.gateway.security;

public record PostAuthRateLimitDecision(
        boolean allowed,
        String failureCode,
        long limit,
        long remaining,
        long resetAfterSeconds,
        long retryAfterSeconds
) {

    public PostAuthRateLimitDecision {
        if (allowed && failureCode != null) {
            throw new IllegalArgumentException(
                    "allowed decision must not have failureCode"
            );
        }
        if (!allowed
                && !"RATE_LIMITED".equals(failureCode)
                && !"QUOTA_EXCEEDED".equals(failureCode)) {
            throw new IllegalArgumentException(
                    "denied decision requires a supported failureCode"
            );
        }
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        if (remaining < 0 || remaining > limit) {
            throw new IllegalArgumentException("remaining is outside limit");
        }
        if (resetAfterSeconds <= 0) {
            throw new IllegalArgumentException(
                    "resetAfterSeconds must be positive"
            );
        }
        if (retryAfterSeconds < 0) {
            throw new IllegalArgumentException(
                    "retryAfterSeconds must not be negative"
            );
        }
        if (allowed && retryAfterSeconds != 0) {
            throw new IllegalArgumentException(
                    "allowed decision must not have retryAfterSeconds"
            );
        }
        if (!allowed && retryAfterSeconds <= 0) {
            throw new IllegalArgumentException(
                    "denied decision requires retryAfterSeconds"
            );
        }
    }
}
