package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthorizedApiRouteTest {

    @Test
    void routeParametersAreDefensivelyCopied() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("userId", "user-123");

        AuthorizedApi api = authorizedApi(parameters);
        parameters.put("userId", "changed");

        assertEquals(Map.of("userId", "user-123"), api.routeParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> api.routeParameters().put("other", "value")
        );
    }

    @Test
    void routeParameterNamesAndValuesAreValidated() {
        assertThrows(
                IllegalArgumentException.class,
                () -> authorizedApi(Map.of("bad name", "value"))
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> authorizedApi(Map.of("id", "has/slash"))
        );
    }

    @Test
    void apiTargetRejectsLocalAndPrivateLiteralHosts() {
        assertThrows(
                IllegalArgumentException.class,
                () -> target("https://localhost/internal")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("https://127.0.0.1/internal")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("https://10.0.0.8/internal")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("https://169.254.169.254/latest")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("https://[::1]/internal")
        );
    }

    private ApiTarget target(String baseUri) {
        return new ApiTarget(
                URI.create(baseUri),
                "GET",
                "/internal",
                Duration.ofSeconds(1)
        );
    }

    private AuthorizedApi authorizedApi(Map<String, String> parameters) {
        return new AuthorizedApi(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "PLATFORM_PUBLIC",
                parameters
        );
    }
}
