package com.apiproject.gateway.security;

@FunctionalInterface
public interface PostAuthLimitGate {

    PostAuthRateLimitDecision check(AuthorizedApi authorizedApi);
}
