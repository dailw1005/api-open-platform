package com.apiproject.gateway.security;

@FunctionalInterface
public interface PreAuthRateLimiter {

    RateLimitDecision check(String clientAddress);
}
