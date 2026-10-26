package com.apiproject.gateway.security;

import java.time.Duration;

public record TokenBucketPolicy(
        long requests,
        Duration window,
        int burst
) {

    public TokenBucketPolicy {
        if (requests <= 0) {
            throw new IllegalArgumentException("requests must be positive");
        }
        if (window == null || window.isNegative() || window.toMillis() <= 0) {
            throw new IllegalArgumentException(
                    "window must be at least one millisecond"
            );
        }
        if (burst <= 0) {
            throw new IllegalArgumentException("burst must be positive");
        }
    }
}
