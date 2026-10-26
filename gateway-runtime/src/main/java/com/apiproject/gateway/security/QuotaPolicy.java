package com.apiproject.gateway.security;

public record QuotaPolicy(
        long dailyLimit,
        long monthlyLimit
) {

    public QuotaPolicy {
        if (dailyLimit <= 0) {
            throw new IllegalArgumentException("dailyLimit must be positive");
        }
        if (monthlyLimit <= 0) {
            throw new IllegalArgumentException("monthlyLimit must be positive");
        }
    }
}
