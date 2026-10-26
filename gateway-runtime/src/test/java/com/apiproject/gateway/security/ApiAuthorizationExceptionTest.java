package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ApiAuthorizationExceptionTest {

    @Test
    void acceptsOnlySupportedCodeAndRetryabilityPairs() {
        assertMapping("API_NOT_FOUND", false);
        assertMapping("API_NOT_GRANTED", false);
        assertMapping("INVALID_CREDENTIAL", false);
        assertMapping("AUTHORIZATION_STORE_UNAVAILABLE", true);
        assertMapping("INTERNAL_CONFIGURATION", false);

        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiAuthorizationException(
                        "API_NOT_FOUND",
                        true,
                        "invalid",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiAuthorizationException(
                        "AUTHORIZATION_STORE_UNAVAILABLE",
                        false,
                        "invalid",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiAuthorizationException(
                        "UNKNOWN",
                        false,
                        "invalid",
                        null
                )
        );
    }

    private void assertMapping(String code, boolean retryable) {
        assertDoesNotThrow(
                () -> new ApiAuthorizationException(
                        code,
                        retryable,
                        "safe",
                        null
                )
        );
    }
}
