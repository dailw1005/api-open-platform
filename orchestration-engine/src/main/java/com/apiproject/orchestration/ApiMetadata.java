package com.apiproject.orchestration;

import java.util.Objects;

public record ApiMetadata(
        String apiRef,
        ApiKind kind,
        boolean idempotent
) {
    public ApiMetadata {
        Objects.requireNonNull(apiRef, "apiRef");
        Objects.requireNonNull(kind, "kind");
    }
}
