package com.apiproject.gateway.security;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public record ApiTarget(
        URI baseUri,
        String method,
        String pathTemplate,
        Duration timeout
) {

    private static final Set<String> ALLOWED_METHODS =
            Set.of("GET", "POST", "PUT", "PATCH", "DELETE");

    public ApiTarget {
        Objects.requireNonNull(baseUri, "baseUri");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(pathTemplate, "pathTemplate");
        Objects.requireNonNull(timeout, "timeout");
        if (!"https".equalsIgnoreCase(baseUri.getScheme())
                || baseUri.getHost() == null
                || baseUri.getUserInfo() != null
                || baseUri.getRawQuery() != null
                || baseUri.getRawFragment() != null) {
            throw new IllegalArgumentException("upstream base URI is unsafe");
        }
        String normalizedMethod = method.toUpperCase(Locale.ROOT);
        if (!ALLOWED_METHODS.contains(normalizedMethod)) {
            throw new IllegalArgumentException("upstream method is invalid");
        }
        if (!pathTemplate.startsWith("/")
                || pathTemplate.contains("//")
                || pathTemplate.contains("?")
                || pathTemplate.contains("#")) {
            throw new IllegalArgumentException(
                    "upstream path template is invalid"
            );
        }
        if (timeout.isNegative()
                || timeout.isZero()
                || timeout.toMillis() > 30_000) {
            throw new IllegalArgumentException("upstream timeout is invalid");
        }
        method = normalizedMethod;
    }
}
