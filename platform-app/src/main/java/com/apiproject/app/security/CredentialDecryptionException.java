package com.apiproject.app.security;

import java.util.Objects;

public final class CredentialDecryptionException extends RuntimeException {

    private final boolean retryable;

    public CredentialDecryptionException(
            boolean retryable,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        this.retryable = retryable;
    }

    public boolean retryable() {
        return retryable;
    }
}
