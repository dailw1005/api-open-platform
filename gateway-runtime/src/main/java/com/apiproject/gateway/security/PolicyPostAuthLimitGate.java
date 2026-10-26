package com.apiproject.gateway.security;

import java.util.Objects;

public final class PolicyPostAuthLimitGate implements PostAuthLimitGate {

    private final PostAuthPolicyResolver policyResolver;
    private final PostAuthRateLimiter rateLimiter;

    public PolicyPostAuthLimitGate(
            PostAuthPolicyResolver policyResolver,
            PostAuthRateLimiter rateLimiter
    ) {
        this.policyResolver = Objects.requireNonNull(
                policyResolver,
                "policyResolver"
        );
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    @Override
    public PostAuthRateLimitDecision check(AuthorizedApi authorizedApi) {
        Objects.requireNonNull(authorizedApi, "authorizedApi");
        PostAuthPolicy policy = policyResolver.resolve(authorizedApi);
        return rateLimiter.check(authorizedApi, policy);
    }
}
