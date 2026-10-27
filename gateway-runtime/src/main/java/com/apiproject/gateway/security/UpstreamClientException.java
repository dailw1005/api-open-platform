package com.apiproject.gateway.security;

import java.util.Objects;

public final class UpstreamClientException extends RuntimeException {

    public enum Code {
        TIMEOUT,
        TRANSPORT,
        RESPONSE_TOO_LARGE
    }

    private final Code code;

    public UpstreamClientException(
            Code code,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message"), cause);
        this.code = Objects.requireNonNull(code, "code");
    }

    public Code code() {
        return code;
    }
}
