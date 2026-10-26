package com.apiproject.app;

import com.apiproject.gateway.security.PostAuthPolicy;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PostAuthLimitPropertiesTest {

    @Test
    void missingValuesUseMandatorySafeDefaults() {
        PostAuthLimitProperties properties = new PostAuthLimitProperties(
                null,
                null,
                null,
                null
        );

        PostAuthPolicy policy = properties.defaultPolicy();

        assertEquals(
                600,
                policy.applicationTokenBucket().requests()
        );
        assertEquals(
                Duration.ofMinutes(1),
                policy.applicationTokenBucket().window()
        );
        assertEquals(120, policy.applicationTokenBucket().burst());
        assertEquals(300, policy.apiTokenBucket().requests());
        assertEquals(60, policy.apiTokenBucket().burst());
        assertEquals(100_000, policy.applicationQuota().dailyLimit());
        assertEquals(2_000_000, policy.applicationQuota().monthlyLimit());
        assertEquals(50_000, policy.apiQuota().dailyLimit());
        assertEquals(1_000_000, policy.apiQuota().monthlyLimit());
    }

    @Test
    void explicitValuesOverrideDefaults() {
        PostAuthLimitProperties properties = new PostAuthLimitProperties(
                new PostAuthLimitProperties.TokenBucket(
                        10,
                        Duration.ofSeconds(30),
                        3
                ),
                new PostAuthLimitProperties.TokenBucket(
                        20,
                        Duration.ofSeconds(60),
                        4
                ),
                new PostAuthLimitProperties.Quota(100, 1_000),
                new PostAuthLimitProperties.Quota(200, 2_000)
        );

        PostAuthPolicy policy = properties.defaultPolicy();

        assertEquals(10, policy.applicationTokenBucket().requests());
        assertEquals(3, policy.applicationTokenBucket().burst());
        assertEquals(20, policy.apiTokenBucket().requests());
        assertEquals(4, policy.apiTokenBucket().burst());
        assertEquals(100, policy.applicationQuota().dailyLimit());
        assertEquals(200, policy.apiQuota().dailyLimit());
    }

    @Test
    void invalidExplicitValuesFailFast() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new PostAuthLimitProperties.TokenBucket(
                        0,
                        Duration.ofMinutes(1),
                        10
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new PostAuthLimitProperties.Quota(0, 10)
        );
    }
}
