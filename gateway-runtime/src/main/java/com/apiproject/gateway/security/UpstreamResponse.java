package com.apiproject.gateway.security;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record UpstreamResponse(
        int status,
        Map<String, List<String>> headers,
        byte[] body
) {

    public UpstreamResponse {
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("upstream status is invalid");
        }
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
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
