package com.apiproject.gateway.security;

import java.time.Duration;

@FunctionalInterface
public interface NonceReplayStore {
    boolean claim(String key, Duration ttl);
}
