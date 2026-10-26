package com.apiproject.gateway.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.JedisPooled;
import redis.embedded.RedisServer;

import java.net.ServerSocket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedisPreAuthRateLimiterTest {

    private static final Instant NOW = Instant.ofEpochSecond(1_760_000_000L);

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
    void fixedWindowAllowsConfiguredRequestsThenDenies() {
        RedisPreAuthRateLimiter limiter = limiter(jedis);

        RateLimitDecision first = limiter.check("203.0.113.10");
        RateLimitDecision second = limiter.check("203.0.113.10");
        RateLimitDecision third = limiter.check("203.0.113.10");

        assertTrue(first.allowed());
        assertEquals(2, first.limit());
        assertEquals(1, first.remaining());
        assertTrue(second.allowed());
        assertEquals(0, second.remaining());
        assertFalse(third.allowed());
        assertEquals(0, third.remaining());
        assertTrue(third.resetAfterSeconds() > 0);
    }

    @Test
    void clientsUseIndependentBuckets() {
        RedisPreAuthRateLimiter limiter = limiter(jedis);

        limiter.check("198.51.100.1");
        limiter.check("198.51.100.1");

        assertTrue(limiter.check("198.51.100.2").allowed());
    }

    @Test
    void redisFailureFailsClosed() {
        JedisPooled failingJedis = mock(JedisPooled.class);
        when(failingJedis.eval(anyString(), anyList(), anyList()))
                .thenThrow(new IllegalStateException("redis down"));
        RedisPreAuthRateLimiter limiter = limiter(failingJedis);

        PreAuthRateLimitException exception = assertThrows(
                PreAuthRateLimitException.class,
                () -> limiter.check("203.0.113.10")
        );

        assertEquals("RATE_LIMIT_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
        assertFalse(exception.getMessage().contains("redis down"));
    }

    private RedisPreAuthRateLimiter limiter(JedisPooled client) {
        return new RedisPreAuthRateLimiter(
                client,
                2,
                Duration.ofSeconds(60),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }
}
