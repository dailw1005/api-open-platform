package com.apiproject.gateway.security;

@FunctionalInterface
public interface PostAuthRateLimiter {

    PostAuthRateLimitDecision check(
            AuthorizedApi authorizedApi,
            PostAuthPolicy policy
    );
}
