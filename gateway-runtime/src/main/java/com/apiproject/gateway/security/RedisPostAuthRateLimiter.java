package com.apiproject.gateway.security;

import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.Protocol;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;

public final class RedisPostAuthRateLimiter implements PostAuthRateLimiter {

    private static final String KEY_PREFIX = "apip:limit:postauth:v1:";
    private static final String LIMIT_SCRIPT = """
            local now_millis = tonumber(ARGV[15])
            local now_seconds = math.floor(now_millis / 1000)

            local function token_state(key, requests, window_millis, burst)
                local stored = redis.call('HMGET', key, 'tokens', 'timestamp')
                local tokens = tonumber(stored[1])
                local timestamp = tonumber(stored[2])
                if not tokens then
                    tokens = burst
                end
                if not timestamp or timestamp > now_millis then
                    timestamp = now_millis
                end

                local refill_per_millis = requests / window_millis
                local elapsed = math.max(0, now_millis - timestamp)
                tokens = math.min(
                    burst,
                    tokens + (elapsed * refill_per_millis)
                )

                local allowed = tokens >= 1
                local after = tokens
                if allowed then
                    after = tokens - 1
                end

                local remaining = math.max(0, math.floor(after))
                local retry_seconds = 0
                if tokens < 1 then
                    retry_seconds = math.max(
                        1,
                        math.ceil(
                            ((1 - tokens) / refill_per_millis) / 1000
                        )
                    )
                end

                local reset_seconds = 1
                if after < burst then
                    reset_seconds = math.max(
                        1,
                        math.ceil(
                            ((burst - after) / refill_per_millis) / 1000
                        )
                    )
                end

                local ttl_millis = math.max(
                    1000,
                    math.ceil((burst / refill_per_millis) + window_millis)
                )
                return {
                    allowed and 1 or 0,
                    after,
                    remaining,
                    reset_seconds,
                    retry_seconds,
                    ttl_millis
                }
            end

            local function quota_state(key, limit, boundary_epoch)
                local current = tonumber(redis.call('GET', key) or '0')
                local allowed = current < limit
                local after = current
                if allowed then
                    after = current + 1
                end
                local remaining = math.max(0, limit - after)
                local reset_seconds = math.max(
                    1,
                    boundary_epoch - now_seconds
                )
                return {
                    allowed and 1 or 0,
                    after,
                    remaining,
                    reset_seconds,
                    reset_seconds
                }
            end

            local app_token = token_state(
                KEYS[1],
                tonumber(ARGV[1]),
                tonumber(ARGV[2]),
                tonumber(ARGV[3])
            )
            local api_token = token_state(
                KEYS[2],
                tonumber(ARGV[4]),
                tonumber(ARGV[5]),
                tonumber(ARGV[6])
            )
            local app_daily = quota_state(
                KEYS[3],
                tonumber(ARGV[7]),
                tonumber(ARGV[11])
            )
            local app_monthly = quota_state(
                KEYS[4],
                tonumber(ARGV[8]),
                tonumber(ARGV[12])
            )
            local api_daily = quota_state(
                KEYS[5],
                tonumber(ARGV[9]),
                tonumber(ARGV[13])
            )
            local api_monthly = quota_state(
                KEYS[6],
                tonumber(ARGV[10]),
                tonumber(ARGV[14])
            )

            local allowed =
                app_token[1] == 1
                and api_token[1] == 1
                and app_daily[1] == 1
                and app_monthly[1] == 1
                and api_daily[1] == 1
                and api_monthly[1] == 1

            if not allowed then
                local failure_code = 0
                local failure_limit = 0
                local failure_reset = 0
                local failure_retry = 0

                local function consider_failure(code, limit, reset, retry)
                    if reset > failure_reset
                            or (reset == failure_reset and retry > failure_retry) then
                        failure_code = code
                        failure_limit = limit
                        failure_reset = reset
                        failure_retry = retry
                    end
                end

                if app_token[1] == 0 then
                    consider_failure(
                        1,
                        tonumber(ARGV[3]),
                        app_token[4],
                        app_token[5]
                    )
                end
                if api_token[1] == 0 then
                    consider_failure(
                        1,
                        tonumber(ARGV[6]),
                        api_token[4],
                        api_token[5]
                    )
                end
                if app_daily[1] == 0 then
                    consider_failure(
                        2,
                        tonumber(ARGV[7]),
                        app_daily[4],
                        app_daily[5]
                    )
                end
                if app_monthly[1] == 0 then
                    consider_failure(
                        2,
                        tonumber(ARGV[8]),
                        app_monthly[4],
                        app_monthly[5]
                    )
                end
                if api_daily[1] == 0 then
                    consider_failure(
                        2,
                        tonumber(ARGV[9]),
                        api_daily[4],
                        api_daily[5]
                    )
                end
                if api_monthly[1] == 0 then
                    consider_failure(
                        2,
                        tonumber(ARGV[10]),
                        api_monthly[4],
                        api_monthly[5]
                    )
                end

                return {
                    0,
                    failure_code,
                    failure_limit,
                    0,
                    failure_reset,
                    failure_retry
                }
            end

            redis.call(
                'HSET',
                KEYS[1],
                'tokens',
                app_token[2],
                'timestamp',
                now_millis
            )
            redis.call('PEXPIRE', KEYS[1], app_token[6])
            redis.call(
                'HSET',
                KEYS[2],
                'tokens',
                api_token[2],
                'timestamp',
                now_millis
            )
            redis.call('PEXPIRE', KEYS[2], api_token[6])
            redis.call('INCR', KEYS[3])
            redis.call('EXPIREAT', KEYS[3], ARGV[11])
            redis.call('INCR', KEYS[4])
            redis.call('EXPIREAT', KEYS[4], ARGV[12])
            redis.call('INCR', KEYS[5])
            redis.call('EXPIREAT', KEYS[5], ARGV[13])
            redis.call('INCR', KEYS[6])
            redis.call('EXPIREAT', KEYS[6], ARGV[14])

            local best_limit = tonumber(ARGV[3])
            local best_remaining = app_token[3]
            local best_reset = app_token[4]
            local best_ratio = best_remaining / best_limit

            local function consider_allow(limit, remaining, reset)
                local ratio = remaining / limit
                if ratio < best_ratio
                        or (ratio == best_ratio and reset > best_reset) then
                    best_limit = limit
                    best_remaining = remaining
                    best_reset = reset
                    best_ratio = ratio
                end
            end

            consider_allow(
                tonumber(ARGV[6]),
                api_token[3],
                api_token[4]
            )
            consider_allow(
                tonumber(ARGV[7]),
                app_daily[3],
                app_daily[4]
            )
            consider_allow(
                tonumber(ARGV[8]),
                app_monthly[3],
                app_monthly[4]
            )
            consider_allow(
                tonumber(ARGV[9]),
                api_daily[3],
                api_daily[4]
            )
            consider_allow(
                tonumber(ARGV[10]),
                api_monthly[3],
                api_monthly[4]
            )

            return {
                1,
                0,
                best_limit,
                best_remaining,
                best_reset,
                0
            }
            """;

    private final JedisPooled jedis;

    public RedisPostAuthRateLimiter(JedisPooled jedis) {
        this.jedis = Objects.requireNonNull(jedis, "jedis");
    }

    @Override
    public PostAuthRateLimitDecision check(
            AuthorizedApi authorizedApi,
            PostAuthPolicy policy
    ) {
        Objects.requireNonNull(authorizedApi, "authorizedApi");
        Objects.requireNonNull(policy, "policy");

        try {
            Instant redisNow = redisNow();
            LocalDate date = redisNow.atZone(ZoneOffset.UTC).toLocalDate();
            YearMonth month = YearMonth.from(date);
            List<String> keys = List.of(
                    KEY_PREFIX + "token:app:" + authorizedApi.appId(),
                    KEY_PREFIX + "token:api:" + authorizedApi.apiId(),
                    KEY_PREFIX + "quota:app:" + authorizedApi.appId()
                            + ":day:" + date,
                    KEY_PREFIX + "quota:app:" + authorizedApi.appId()
                            + ":month:" + month,
                    KEY_PREFIX + "quota:api:" + authorizedApi.apiId()
                            + ":day:" + date,
                    KEY_PREFIX + "quota:api:" + authorizedApi.apiId()
                            + ":month:" + month
            );
            List<String> arguments = List.of(
                    Long.toString(policy.applicationTokenBucket().requests()),
                    Long.toString(
                            policy.applicationTokenBucket().window().toMillis()
                    ),
                    Integer.toString(policy.applicationTokenBucket().burst()),
                    Long.toString(policy.apiTokenBucket().requests()),
                    Long.toString(policy.apiTokenBucket().window().toMillis()),
                    Integer.toString(policy.apiTokenBucket().burst()),
                    Long.toString(policy.applicationQuota().dailyLimit()),
                    Long.toString(policy.applicationQuota().monthlyLimit()),
                    Long.toString(policy.apiQuota().dailyLimit()),
                    Long.toString(policy.apiQuota().monthlyLimit()),
                    Long.toString(dayBoundaryEpochSecond(date)),
                    Long.toString(monthBoundaryEpochSecond(month)),
                    Long.toString(dayBoundaryEpochSecond(date)),
                    Long.toString(monthBoundaryEpochSecond(month)),
                    Long.toString(redisNow.toEpochMilli())
            );
            Object result = jedis.eval(LIMIT_SCRIPT, keys, arguments);
            if (!(result instanceof List<?> values) || values.size() != 6) {
                throw new IllegalStateException("invalid Redis post-auth result");
            }
            long allowed = toLong(values.get(0));
            long failure = toLong(values.get(1));
            long limit = toLong(values.get(2));
            long remaining = toLong(values.get(3));
            long reset = toLong(values.get(4));
            long retry = toLong(values.get(5));

            String failureCode = switch ((int) failure) {
                case 0 -> null;
                case 1 -> "RATE_LIMITED";
                case 2 -> "QUOTA_EXCEEDED";
                default -> throw new IllegalStateException(
                        "invalid Redis post-auth failure code"
                );
            };
            if (allowed != 0 && allowed != 1) {
                throw new IllegalStateException(
                        "invalid Redis post-auth allowed value"
                );
            }
            return new PostAuthRateLimitDecision(
                    allowed == 1,
                    failureCode,
                    limit,
                    remaining,
                    reset,
                    retry
            );
        } catch (RuntimeException exception) {
            throw new PostAuthRateLimitException(
                    "RATE_LIMIT_UNAVAILABLE",
                    true,
                    "Post-authentication rate limiter is unavailable",
                    exception
            );
        }
    }

    private Instant redisNow() {
        Object response = jedis.sendCommand(Protocol.Command.TIME);
        if (!(response instanceof List<?> values) || values.size() != 2) {
            throw new IllegalStateException("invalid Redis TIME response");
        }
        long seconds = toLong(values.get(0));
        long micros = toLong(values.get(1));
        return Instant.ofEpochSecond(seconds, micros * 1_000);
    }

    private long dayBoundaryEpochSecond(LocalDate date) {
        return date.plusDays(1)
                .atStartOfDay(ZoneOffset.UTC)
                .toEpochSecond();
    }

    private long monthBoundaryEpochSecond(YearMonth month) {
        return month.plusMonths(1)
                .atDay(1)
                .atStartOfDay(ZoneOffset.UTC)
                .toEpochSecond();
    }

    private long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof byte[] bytes) {
            return Long.parseLong(new String(bytes, StandardCharsets.US_ASCII));
        }
        if (value instanceof String text) {
            return Long.parseLong(text);
        }
        throw new IllegalStateException("invalid Redis post-auth value");
    }
}
