package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProxyValueObjectTest {

    @Test
    void upstreamRequestIsImmutableAndValidated() {
        byte[] body = new byte[]{1, 2, 3};
        List<String> values = new ArrayList<>(List.of("one"));
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("X-Test", values);
        UpstreamRequest request = new UpstreamRequest(
                URI.create("https://api.example.test"),
                "POST",
                headers,
                body,
                Duration.ofSeconds(1)
        );
        body[0] = 9;
        values.add("two");

        assertArrayEquals(new byte[]{1, 2, 3}, request.body());
        request.body()[1] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, request.body());
        assertEquals(List.of("one"), request.headers().get("X-Test"));

        assertThrows(
                IllegalArgumentException.class,
                () -> new UpstreamRequest(
                        URI.create("file:///etc/passwd"),
                        "GET",
                        Map.of(),
                        new byte[0],
                        Duration.ofSeconds(1)
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new UpstreamRequest(
                        URI.create("https://api.example.test"),
                        "GET",
                        Map.of(),
                        new byte[0],
                        Duration.ZERO
                )
        );
    }

    @Test
    void upstreamResponseIsImmutableAndValidated() {
        byte[] body = new byte[]{4, 5};
        UpstreamResponse response = new UpstreamResponse(
                200,
                Map.of("X-Test", List.of("one")),
                body
        );
        body[0] = 9;

        assertArrayEquals(new byte[]{4, 5}, response.body());
        response.body()[1] = 9;
        assertArrayEquals(new byte[]{4, 5}, response.body());

        assertThrows(
                IllegalArgumentException.class,
                () -> new UpstreamResponse(99, Map.of(), new byte[0])
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new UpstreamResponse(600, Map.of(), new byte[0])
        );
    }

    @Test
    void routeExpanderRejectsMalformedRemainingBraces() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RouteTemplateExpander.expand(
                        "/items/{valid}/{broken",
                        Map.of("valid", "one")
                )
        );
    }

    @Test
    void targetResolutionExceptionOnlyAllowsConfigurationMapping() {
        ApiTargetResolutionException exception =
                new ApiTargetResolutionException(
                        "UPSTREAM_CONFIGURATION_ERROR",
                        false,
                        "invalid",
                        null
                );

        assertEquals("UPSTREAM_CONFIGURATION_ERROR", exception.code());
        assertEquals(false, exception.retryable());
        ApiTargetResolutionException unavailable =
                new ApiTargetResolutionException(
                        "TARGET_STORE_UNAVAILABLE",
                        true,
                        "unavailable",
                        null
                );
        assertEquals("TARGET_STORE_UNAVAILABLE", unavailable.code());
        assertEquals(true, unavailable.retryable());
        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiTargetResolutionException(
                        "UPSTREAM_CONFIGURATION_ERROR",
                        true,
                        "invalid",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiTargetResolutionException(
                        "UNKNOWN",
                        false,
                        "invalid",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ApiTargetResolutionException(
                        "TARGET_STORE_UNAVAILABLE",
                        false,
                        "invalid",
                        null
                )
        );
    }

    @Test
    void authorizedApiRequiresRouteParameterMap() {
        assertThrows(
                NullPointerException.class,
                () -> new AuthorizedApi(
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        "PLATFORM_PUBLIC",
                        null
                )
        );
    }
}
