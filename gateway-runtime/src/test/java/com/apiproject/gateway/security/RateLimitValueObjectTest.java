package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class RateLimitValueObjectTest {

    @Test
    void rateLimitDecisionRejectsInvalidValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RateLimitDecision(true, 0, 0, 1)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new RateLimitDecision(true, 1, -1, 1)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new RateLimitDecision(true, 1, 2, 1)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new RateLimitDecision(true, 1, 1, -1)
        );
    }

    @Test
    void rateLimitExceptionRejectsInvalidMapping() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new PreAuthRateLimitException(
                        "UNKNOWN",
                        true,
                        "safe",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new PreAuthRateLimitException(
                        "RATE_LIMIT_UNAVAILABLE",
                        false,
                        "safe",
                        null
                )
        );
    }
}
