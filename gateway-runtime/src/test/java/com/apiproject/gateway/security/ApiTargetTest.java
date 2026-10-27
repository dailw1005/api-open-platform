package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ApiTargetTest {

    @Test
    void normalizesValidMethodAndAcceptsPublicDnsTarget() {
        ApiTarget target = new ApiTarget(
                URI.create("https://api.example.test/base"),
                "patch",
                "/items",
                Duration.ofSeconds(1)
        );

        assertEquals("PATCH", target.method());
    }

    @Test
    void rejectsUnsafeBaseUriShapes() {
        for (String uri : List.of(
                "http://api.example.test/base",
                "https:///missing-host",
                "https://user@api.example.test/base",
                "https://api.example.test/base?debug=true",
                "https://api.example.test/base#fragment",
                "https://api.example.test/base/../internal",
                "https://api.example.test/base/%2e%2e/internal",
                "https://api.example.test/base\\internal"
        )) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new ApiTarget(
                            URI.create(uri),
                            "GET",
                            "/items",
                            Duration.ofSeconds(1)
                    )
            );
        }
    }

    @Test
    void rejectsUnsafeLiteralAddressFamilies() {
        for (String host : List.of(
                "localhost",
                "service.localhost",
                "0.0.0.0",
                "127.0.0.1",
                "10.0.0.1",
                "169.254.169.254",
                "224.0.0.1",
                "100.64.0.1",
                "192.0.0.10",
                "198.18.0.1",
                "[::1]",
                "[fc00::1]"
        )) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new ApiTarget(
                            URI.create("https://" + host + "/base"),
                            "GET",
                            "/items",
                            Duration.ofSeconds(1)
                    )
            );
        }
        assertEquals(
                "GET",
                new ApiTarget(
                        URI.create("https://93.184.216.34/base"),
                        "GET",
                        "/items",
                        Duration.ofSeconds(1)
                ).method()
        );
    }

    @Test
    void rejectsInvalidMethodPathAndTimeout() {
        assertThrows(
                IllegalArgumentException.class,
                () -> target("TRACE", "/items", Duration.ofSeconds(1))
        );
        for (String path : List.of(
                "relative",
                "/items//nested",
                "/items?debug=true",
                "/items#fragment"
        )) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> target("GET", path, Duration.ofSeconds(1))
            );
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> target("GET", "/items", Duration.ofSeconds(-1))
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("GET", "/items", Duration.ZERO)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> target("GET", "/items", Duration.ofSeconds(31))
        );
    }

    private ApiTarget target(
            String method,
            String path,
            Duration timeout
    ) {
        return new ApiTarget(
                URI.create("https://api.example.test"),
                method,
                path,
                timeout
        );
    }
}
