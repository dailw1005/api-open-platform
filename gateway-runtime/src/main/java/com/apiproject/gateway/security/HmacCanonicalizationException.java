package com.apiproject.gateway.security;

import java.util.Objects;

public final class HmacCanonicalizationException extends RuntimeException {

    private final String code;

    public HmacCanonicalizationException(String code, String message) {
        super(Objects.requireNonNull(message, "message"));
        this.code = Objects.requireNonNull(code, "code");
    }

    public String code() {
        return code;
    }
}
