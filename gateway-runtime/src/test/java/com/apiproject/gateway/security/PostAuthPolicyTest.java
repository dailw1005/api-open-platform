package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PostAuthPolicyTest {

    @Test
    void tokenBucketRequiresPositiveRateWindowAndBurst() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new TokenBucketPolicy(0, Duration.ofMinutes(1), 10)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new TokenBucketPolicy(10, Duration.ofNanos(1), 10)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new TokenBucketPolicy(10, Duration.ofMinutes(1), 0)
        );
    }

    @Test
    void quotaRequiresPositiveDailyAndMonthlyLimits() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new QuotaPolicy(0, 100)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new QuotaPolicy(10, 0)
        );
    }

    @Test
    void postAuthPolicyCombinesApplicationAndApiLimits() {
        TokenBucketPolicy rate = new TokenBucketPolicy(
                60,
                Duration.ofMinutes(1),
                10
        );
        QuotaPolicy quota = new QuotaPolicy(1_000, 20_000);

        PostAuthPolicy policy = new PostAuthPolicy(
                rate,
                rate,
                quota,
                quota
        );

        assertEquals(rate, policy.applicationTokenBucket());
        assertEquals(rate, policy.apiTokenBucket());
        assertEquals(quota, policy.applicationQuota());
        assertEquals(quota, policy.apiQuota());
    }

    @Test
    void authorizedApiRequiresApplicationAndApiIdentity() {
        UUID appId = UUID.randomUUID();
        UUID apiId = UUID.randomUUID();
        UUID apiVersionId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();

        AuthorizedApi api = new AuthorizedApi(
                appId,
                apiId,
                apiVersionId,
                tenantId,
                "PLATFORM_PUBLIC"
        );

        assertEquals(appId, api.appId());
        assertEquals(apiId, api.apiId());
    }
}
