package com.apiproject.gateway.security;

import java.util.Objects;

public final class HmacVerificationException extends RuntimeException {

    private final String code;

    public HmacVerificationException(String code, String message) {
        super(Objects.requireNonNull(message, "message"));
        this.code = Objects.requireNonNull(code, "code");
    }

    public String code() {
        return code;
    }
}
