package com.apiproject.gateway.security;

public record RateLimitDecision(
        boolean allowed,
        int limit,
        int remaining,
        long resetAfterSeconds
) {

    public RateLimitDecision {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        if (remaining < 0 || remaining > limit) {
            throw new IllegalArgumentException("remaining is outside limit");
        }
        if (resetAfterSeconds < 0) {
            throw new IllegalArgumentException("resetAfterSeconds must not be negative");
        }
    }
}
