package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacRequestAuthenticatorTest {

    private static final byte[] SECRET = bytes(
            "test-secret-0123456789abcdef0123456789abcdef"
    );
    private static final Instant NOW = Instant.ofEpochSecond(1_760_000_000L);

    private final RecordingStore store = new RecordingStore();
    private final HmacCanonicalizer canonicalizer = HmacCanonicalizer.createDefault();
    private final HmacRequestAuthenticator authenticator = new HmacRequestAuthenticator(
            HmacVerifier.createDefault(),
            NonceReplayGuard.createDefault(store)
    );

    @Test
    void authenticatesOnceAndRejectsReplay() {
        HmacCanonicalRequest request = request();
        String signature = sign(request);

        assertDoesNotThrow(() -> authenticator.authenticate(
                request,
                signature,
                SECRET,
                NOW
        ));
        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                () -> authenticator.authenticate(request, signature, SECRET, NOW)
        );

        assertEquals("NONCE_REPLAYED", exception.code());
    }

    @Test
    void invalidSignatureDoesNotConsumeNonce() {
        HmacCanonicalRequest request = request();

        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                () -> authenticator.authenticate(
                        request,
                        "0".repeat(64),
                        SECRET,
                        NOW
                )
        );

        assertEquals("INVALID_SIGNATURE", exception.code());
        assertEquals(0, store.attempts);
    }

    @Test
    void staleTimestampDoesNotConsumeNonce() {
        HmacCanonicalRequest request = request();
        String signature = sign(request);

        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                () -> authenticator.authenticate(
                        request,
                        signature,
                        SECRET,
                        NOW.plusSeconds(301)
                )
        );

        assertEquals("TIMESTAMP_OUT_OF_WINDOW", exception.code());
        assertEquals(0, store.attempts);
    }

    private HmacCanonicalRequest request() {
        return new HmacCanonicalRequest(
                "ak_test_1234567890abcdef",
                "GET",
                "api.example.com",
                "/v1/users",
                null,
                null,
                1_760_000_000L,
                "abcdefghijklmnop",
                bytes("")
        );
    }

    private String sign(HmacCanonicalRequest request) {
        return canonicalizer.canonicalize(request, SECRET).signatureHex();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static final class RecordingStore implements NonceReplayStore {
        private final Set<String> claimed = new HashSet<>();
        private int attempts;

        @Override
        public boolean claim(String key, Duration ttl) {
            attempts++;
            return claimed.add(key);
        }
    }
}
