package com.apiproject.gateway.security;

import java.util.Objects;

public record HmacCanonicalResult(
        String canonicalString,
        String signatureHex
) {
    public HmacCanonicalResult {
        Objects.requireNonNull(canonicalString, "canonicalString");
        Objects.requireNonNull(signatureHex, "signatureHex");
    }

    @Override
    public String toString() {
        return "HmacCanonicalResult[redacted]";
    }
}
