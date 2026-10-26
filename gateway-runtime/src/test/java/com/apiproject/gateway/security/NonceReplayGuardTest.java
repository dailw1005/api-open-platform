package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NonceReplayGuardTest {

    private static final String APP_KEY = "ak_test_1234567890abcdef";
    private static final String NONCE = "abcdefghijklmnop";

    @Test
    void acceptsFirstUseAndRejectsReplay() {
        RecordingStore store = new RecordingStore();
        NonceReplayGuard guard = NonceReplayGuard.createDefault(store);

        assertDoesNotThrow(() -> guard.assertUnused(APP_KEY, NONCE));
        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                () -> guard.assertUnused(APP_KEY, NONCE)
        );

        assertEquals("NONCE_REPLAYED", exception.code());
        assertEquals(2, store.attempts);
    }

    @Test
    void usesHashedNonceKeyAndBoundedTtl() {
        RecordingStore store = new RecordingStore();
        NonceReplayGuard guard = NonceReplayGuard.createDefault(store);

        guard.assertUnused(APP_KEY, NONCE);

        assertTrue(store.lastKey.startsWith("apip:auth:nonce:v1:"));
        assertEquals(19 + 64, store.lastKey.length());
        assertFalse(store.lastKey.contains(APP_KEY));
        assertFalse(store.lastKey.contains(NONCE));
        assertEquals(Duration.ofSeconds(660), store.lastTtl);
    }

    @Test
    void differentAppsDoNotShareNonceNamespace() {
        RecordingStore store = new RecordingStore();
        NonceReplayGuard guard = NonceReplayGuard.createDefault(store);

        guard.assertUnused("ak_app_one_1234567890", NONCE);
        String firstKey = store.lastKey;
        guard.assertUnused("ak_app_two_1234567890", NONCE);

        assertFalse(firstKey.equals(store.lastKey));
    }

    @Test
    void failsClosedWhenStoreIsUnavailable() {
        NonceReplayStore store = (key, ttl) -> {
            throw new IllegalStateException("redis down");
        };
        NonceReplayGuard guard = NonceReplayGuard.createDefault(store);

        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                () -> guard.assertUnused(APP_KEY, NONCE)
        );

        assertEquals("NONCE_STORE_UNAVAILABLE", exception.code());
    }

    @Test
    void invalidInputsDoNotReachStore() {
        RecordingStore store = new RecordingStore();
        NonceReplayGuard guard = NonceReplayGuard.createDefault(store);

        assertEquals(
                "INVALID_REQUEST",
                assertThrows(
                        HmacVerificationException.class,
                        () -> guard.assertUnused("bad key", NONCE)
                ).code()
        );
        assertEquals(
                "INVALID_REQUEST",
                assertThrows(
                        HmacVerificationException.class,
                        () -> guard.assertUnused(APP_KEY, "short")
                ).code()
        );
        assertEquals(0, store.attempts);
    }

    private static final class RecordingStore implements NonceReplayStore {
        private final Set<String> claimed = new HashSet<>();
        private int attempts;
        private String lastKey;
        private Duration lastTtl;

        @Override
        public boolean claim(String key, Duration ttl) {
            attempts++;
            lastKey = key;
            lastTtl = ttl;
            return claimed.add(key);
        }
    }
}
