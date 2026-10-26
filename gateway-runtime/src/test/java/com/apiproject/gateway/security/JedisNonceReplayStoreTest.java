package com.apiproject.gateway.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.JedisPooled;
import redis.embedded.RedisServer;

import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JedisNonceReplayStoreTest {

    private static RedisServer redisServer;
    private static JedisPooled jedis;
    private static JedisNonceReplayStore store;

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
        store = new JedisNonceReplayStore(jedis);
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
    void firstClaimWinsAndTtlIsBounded() {
        String key = "apip:auth:nonce:v1:redis-test";

        assertTrue(store.claim(key, Duration.ofSeconds(60)));
        assertFalse(store.claim(key, Duration.ofSeconds(60)));
        long ttlMillis = jedis.pttl(key);
        assertTrue(ttlMillis > 0);
        assertTrue(ttlMillis <= 60_000);
    }

    @Test
    void concurrentClaimsHaveSingleWinner() throws Exception {
        String key = "apip:auth:nonce:v1:redis-concurrent";
        int contenders = 16;
        ExecutorService executor = Executors.newFixedThreadPool(contenders);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();

        try {
            for (int index = 0; index < contenders; index++) {
                results.add(executor.submit(() -> {
                    start.await();
                    return store.claim(key, Duration.ofSeconds(60));
                }));
            }
            start.countDown();

            int winners = 0;
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    winners++;
                }
            }
            assertEquals(1, winners);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void rejectsNonPositiveTtlBeforeRedisCommand() {
        assertThrows(
                IllegalArgumentException.class,
                () -> store.claim(
                        "apip:auth:nonce:v1:invalid-ttl",
                        Duration.ZERO
                )
        );
        assertEquals(-2, jedis.pttl("apip:auth:nonce:v1:invalid-ttl"));
    }
}
