package com.apiproject.gateway.security;

import java.util.Objects;

public record HmacCanonicalRequest(
        String appKey,
        String method,
        String host,
        String rawPath,
        String rawQuery,
        String contentType,
        long timestampSeconds,
        String nonce,
        byte[] body
) {
    public HmacCanonicalRequest {
        Objects.requireNonNull(appKey, "appKey");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(rawPath, "rawPath");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(body, "body");
        body = body.clone();
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    @Override
    public String toString() {
        return "HmacCanonicalRequest["
                + "appKey=" + appKey
                + ", method=" + method
                + ", host=" + host
                + ", rawPath=" + rawPath
                + ", timestampSeconds=" + timestampSeconds
                + ']';
    }
}
