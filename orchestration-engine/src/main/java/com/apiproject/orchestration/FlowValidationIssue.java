package com.apiproject.orchestration;

import java.util.Objects;

public record FlowValidationIssue(
        String pointer,
        String code,
        String message
) {
    public FlowValidationIssue {
        Objects.requireNonNull(pointer, "pointer");
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
    }
}
