package com.apiproject.gateway.security;

import redis.clients.jedis.JedisPooled;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public final class RedisPreAuthRateLimiter implements PreAuthRateLimiter {

    private static final String KEY_PREFIX = "apip:rate:preauth:v1:";
    private static final String INCREMENT_SCRIPT = """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            local ttl = redis.call('PTTL', KEYS[1])
            return {current, ttl}
            """;

    private final JedisPooled jedis;
    private final int limit;
    private final Duration window;
    private final Clock clock;

    public RedisPreAuthRateLimiter(
            JedisPooled jedis,
            int limit,
            Duration window,
            Clock clock
    ) {
        this.jedis = Objects.requireNonNull(jedis, "jedis");
        this.limit = limit;
        this.window = Objects.requireNonNull(window, "window");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        if (window.isNegative() || window.toMillis() <= 0) {
            throw new IllegalArgumentException(
                    "window must be at least one millisecond"
            );
        }
    }

    @Override
    public RateLimitDecision check(String clientAddress) {
        String address = clientAddress == null || clientAddress.isBlank()
                ? "unknown"
                : clientAddress;
        long windowMillis = window.toMillis();
        long bucket = clock.millis() / windowMillis;
        String key = KEY_PREFIX + bucket + ":" + hash(address);
        try {
            Object result = jedis.eval(
                    INCREMENT_SCRIPT,
                    List.of(key),
                    List.of(Long.toString(windowMillis))
            );
            if (!(result instanceof List<?> values) || values.size() != 2) {
                throw new IllegalStateException("invalid Redis rate-limit result");
            }
            long count = toLong(values.get(0));
            long ttlMillis = toLong(values.get(1));
            if (count <= 0 || ttlMillis < 0) {
                throw new IllegalStateException("invalid Redis rate-limit counters");
            }
            long resetAfterSeconds = Math.max(1, (ttlMillis + 999) / 1000);
            boolean allowed = count <= limit;
            int remaining = allowed ? (int) Math.max(0, limit - count) : 0;
            return new RateLimitDecision(
                    allowed,
                    limit,
                    remaining,
                    resetAfterSeconds
            );
        } catch (RuntimeException exception) {
            throw new PreAuthRateLimitException(
                    "RATE_LIMIT_UNAVAILABLE",
                    true,
                    "Pre-authentication rate limiter is unavailable",
                    exception
            );
        }
    }

    private long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        throw new IllegalStateException("invalid Redis rate-limit value");
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
