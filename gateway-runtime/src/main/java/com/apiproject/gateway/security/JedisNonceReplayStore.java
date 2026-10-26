package com.apiproject.gateway.security;

import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.params.SetParams;

import java.time.Duration;
import java.util.Objects;

public final class JedisNonceReplayStore implements NonceReplayStore {

    private final JedisPooled jedis;

    public JedisNonceReplayStore(JedisPooled jedis) {
        this.jedis = Objects.requireNonNull(jedis, "jedis");
    }

    @Override
    public boolean claim(String key, Duration ttl) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        String result = jedis.set(
                key,
                "1",
                SetParams.setParams()
                        .nx()
                        .px(ttl.toMillis())
        );
        return "OK".equals(result);
    }
}
