package com.apiproject.gateway.security;

import java.util.Objects;

public final class CredentialResolutionException extends RuntimeException {

    private final String code;
    private final boolean retryable;

    public CredentialResolutionException(
            String code,
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        this.code = validateCode(code, retryable);
        this.retryable = retryable;
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }

    private String validateCode(String code, boolean retryable) {
        Objects.requireNonNull(code, "code");
        if ("CREDENTIAL_STORE_UNAVAILABLE".equals(code) && retryable) {
            return code;
        }
        if ("INTERNAL_CONFIGURATION".equals(code) && !retryable) {
            return code;
        }
        throw new IllegalArgumentException("unsupported credential error mapping");
    }
}
