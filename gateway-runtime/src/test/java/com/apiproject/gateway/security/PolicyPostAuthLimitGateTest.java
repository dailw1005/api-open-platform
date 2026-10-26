package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class PolicyPostAuthLimitGateTest {

    @Test
    void resolvesPolicyThenChecksAuthenticatedApplicationAndApi() {
        AuthorizedApi api = new AuthorizedApi(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "PLATFORM_PUBLIC"
        );
        TokenBucketPolicy rate = new TokenBucketPolicy(
                10,
                Duration.ofMinutes(1),
                5
        );
        QuotaPolicy quota = new QuotaPolicy(100, 1_000);
        PostAuthPolicy policy = new PostAuthPolicy(
                rate,
                rate,
                quota,
                quota
        );
        PostAuthRateLimitDecision expected = new PostAuthRateLimitDecision(
                true,
                null,
                5,
                4,
                1,
                0
        );
        AtomicReference<AuthorizedApi> resolvedApi = new AtomicReference<>();
        AtomicReference<PostAuthPolicy> checkedPolicy = new AtomicReference<>();
        PostAuthPolicyResolver resolver = requested -> {
            resolvedApi.set(requested);
            return policy;
        };
        PostAuthRateLimiter limiter = (requested, requestedPolicy) -> {
            assertSame(api, requested);
            checkedPolicy.set(requestedPolicy);
            return expected;
        };

        PostAuthRateLimitDecision actual =
                new PolicyPostAuthLimitGate(resolver, limiter).check(api);

        assertEquals(api, resolvedApi.get());
        assertSame(policy, checkedPolicy.get());
        assertEquals(expected, actual);
    }
}
