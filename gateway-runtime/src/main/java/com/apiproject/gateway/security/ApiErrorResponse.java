package com.apiproject.gateway.security;

public record ApiErrorResponse(
        String code,
        String message,
        String requestId,
        boolean retryable
) {
}
