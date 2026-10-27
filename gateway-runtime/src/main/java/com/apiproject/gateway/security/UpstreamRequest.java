package com.apiproject.gateway.security;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record UpstreamRequest(
        URI uri,
        String method,
        Map<String, List<String>> headers,
        byte[] body,
        Duration timeout
) {

    public UpstreamRequest {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(timeout, "timeout");
        if (!"http".equalsIgnoreCase(uri.getScheme())
                && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("upstream URI scheme is invalid");
        }
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("upstream timeout is invalid");
        }
        Map<String, List<String>> headerCopy = new LinkedHashMap<>();
        headers.forEach((name, values) -> {
            Objects.requireNonNull(name, "header name");
            Objects.requireNonNull(values, "header values");
            headerCopy.put(name, List.copyOf(values));
        });
        headers = Map.copyOf(headerCopy);
        body = body.clone();
    }

    @Override
    public byte[] body() {
        return body.clone();
    }
}
