package com.apiproject.gateway.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.JedisPooled;
import redis.embedded.RedisServer;

import java.net.ServerSocket;
import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedisPostAuthRateLimiterTest {

    private static final TokenBucketPolicy HIGH_RATE = new TokenBucketPolicy(
            10_000,
            Duration.ofMinutes(1),
            10_000
    );
    private static final QuotaPolicy HIGH_QUOTA = new QuotaPolicy(
            1_000_000,
            10_000_000
    );

    private static RedisServer redisServer;
    private static JedisPooled jedis;

    @BeforeAll
    static void startRedis() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        redisServer = RedisServer.newRedisServer()
                .port(port)
                .setting("bind 127.0.0.1")
                .setting("save \"\"")
                .setting("appendonly no")
                .build();
        redisServer.start();
        jedis = new JedisPooled("127.0.0.1", port);
    }

    @AfterAll
    static void stopRedis() throws Exception {
        if (jedis != null) {
            jedis.close();
        }
        if (redisServer != null) {
            redisServer.stop();
        }
    }

    @Test
    void applicationTokenBucketAllowsBurstThenRejects() {
        RedisPostAuthRateLimiter limiter = limiter(jedis);
        AuthorizedApi api = authorizedApi();
        PostAuthPolicy policy = policy(
                new TokenBucketPolicy(2, Duration.ofHours(1), 2),
                HIGH_RATE,
                HIGH_QUOTA,
                HIGH_QUOTA
        );

        PostAuthRateLimitDecision first = limiter.check(api, policy);
        PostAuthRateLimitDecision second = limiter.check(api, policy);
        PostAuthRateLimitDecision third = limiter.check(api, policy);

        assertTrue(first.allowed());
        assertEquals(1, first.remaining());
        assertTrue(second.allowed());
        assertEquals(0, second.remaining());
        assertFalse(third.allowed());
        assertEquals("RATE_LIMITED", third.failureCode());
        assertEquals(0, third.remaining());
        assertTrue(third.retryAfterSeconds() > 0);
    }

    @Test
    void apiRejectionDoesNotConsumeApplicationTokens() {
        RedisPostAuthRateLimiter limiter = limiter(jedis);
        AuthorizedApi api = authorizedApi();
        TokenBucketPolicy applicationRate = new TokenBucketPolicy(
                2,
                Duration.ofHours(1),
                2
        );
        PostAuthPolicy blockedByApi = policy(
                applicationRate,
                new TokenBucketPolicy(1, Duration.ofHours(1), 1),
                HIGH_QUOTA,
                HIGH_QUOTA
        );
        PostAuthPolicy apiRelaxed = policy(
                applicationRate,
                HIGH_RATE,
                HIGH_QUOTA,
                HIGH_QUOTA
        );

        assertTrue(limiter.check(api, blockedByApi).allowed());
        assertFalse(limiter.check(api, blockedByApi).allowed());
        assertTrue(
                limiter.check(authorizedApiWithSameApp(api), apiRelaxed)
                        .allowed()
        );
    }

    @Test
    void quotaRejectionDoesNotConsumeTokenBuckets() {
        RedisPostAuthRateLimiter limiter = limiter(jedis);
        AuthorizedApi api = authorizedApi();
        TokenBucketPolicy applicationRate = new TokenBucketPolicy(
                2,
                Duration.ofHours(1),
                2
        );
        PostAuthPolicy blockedByQuota = policy(
                applicationRate,
                HIGH_RATE,
                new QuotaPolicy(1, 100),
                HIGH_QUOTA
        );
        PostAuthPolicy quotaRelaxed = policy(
                applicationRate,
                HIGH_RATE,
                new QuotaPolicy(2, 100),
                HIGH_QUOTA
        );

        assertTrue(limiter.check(api, blockedByQuota).allowed());
        PostAuthRateLimitDecision denied = limiter.check(api, blockedByQuota);
        assertFalse(denied.allowed());
        assertEquals("QUOTA_EXCEEDED", denied.failureCode());
        assertTrue(limiter.check(api, quotaRelaxed).allowed());
    }

    @Test
    void apiQuotaIsSharedAcrossApplicationsAndTenants() {
        RedisPostAuthRateLimiter limiter = limiter(jedis);
        AuthorizedApi firstApp = authorizedApi();
        AuthorizedApi secondApp = authorizedApiWithSameApiDifferentTenant(
                firstApp
        );
        PostAuthPolicy policy = policy(
                HIGH_RATE,
                HIGH_RATE,
                HIGH_QUOTA,
                new QuotaPolicy(1, 1)
        );

        assertTrue(limiter.check(firstApp, policy).allowed());
        PostAuthRateLimitDecision denied = limiter.check(secondApp, policy);

        assertFalse(denied.allowed());
        assertEquals("QUOTA_EXCEEDED", denied.failureCode());
    }

    @Test
    void monthlyQuotaRejectsAfterDailyAllowanceRemains() {
        RedisPostAuthRateLimiter limiter = limiter(jedis);
        AuthorizedApi api = authorizedApi();
        PostAuthPolicy policy = policy(
                HIGH_RATE,
                HIGH_RATE,
                new QuotaPolicy(10, 1),
                HIGH_QUOTA
        );

        assertTrue(limiter.check(api, policy).allowed());
        PostAuthRateLimitDecision denied = limiter.check(api, policy);

        assertFalse(denied.allowed());
        assertEquals("QUOTA_EXCEEDED", denied.failureCode());
        assertTrue(denied.resetAfterSeconds() > 0);
    }

    @Test
    void redisFailureFailsClosedWithoutLeakingDetails() {
        JedisPooled failingJedis = mock(JedisPooled.class);
        when(failingJedis.eval(anyString(), anyList(), anyList()))
                .thenThrow(new IllegalStateException("redis down"));
        RedisPostAuthRateLimiter limiter = limiter(failingJedis);

        PostAuthRateLimitException exception = assertThrows(
                PostAuthRateLimitException.class,
                () -> limiter.check(authorizedApi(), policy(
                        HIGH_RATE,
                        HIGH_RATE,
                        HIGH_QUOTA,
                        HIGH_QUOTA
                ))
        );

        assertEquals("RATE_LIMIT_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
        assertFalse(exception.getMessage().contains("redis down"));
    }

    private RedisPostAuthRateLimiter limiter(JedisPooled client) {
        return new RedisPostAuthRateLimiter(client);
    }

    private AuthorizedApi authorizedApi() {
        return new AuthorizedApi(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "PLATFORM_PUBLIC"
        );
    }

    private AuthorizedApi authorizedApiWithSameApiDifferentTenant(
            AuthorizedApi source
    ) {
        return new AuthorizedApi(
                UUID.randomUUID(),
                source.apiId(),
                source.apiVersionId(),
                UUID.randomUUID(),
                source.visibility()
        );
    }

    private AuthorizedApi authorizedApiWithSameApp(AuthorizedApi source) {
        return new AuthorizedApi(
                source.appId(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                source.tenantId(),
                source.visibility()
        );
    }

    private PostAuthPolicy policy(
            TokenBucketPolicy applicationRate,
            TokenBucketPolicy apiRate,
            QuotaPolicy applicationQuota,
            QuotaPolicy apiQuota
    ) {
        return new PostAuthPolicy(
                applicationRate,
                apiRate,
                applicationQuota,
                apiQuota
        );
    }
}
