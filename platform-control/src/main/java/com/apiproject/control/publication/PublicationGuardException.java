package com.apiproject.control.publication;

import java.util.Objects;

public final class PublicationGuardException extends RuntimeException {

    private final String code;

    public PublicationGuardException(String code, String message) {
        super(Objects.requireNonNull(message, "message"));
        this.code = Objects.requireNonNull(code, "code");
    }

    public String code() {
        return code;
    }
}
