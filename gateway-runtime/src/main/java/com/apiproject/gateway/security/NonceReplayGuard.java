package com.apiproject.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;
import java.util.regex.Pattern;

public final class NonceReplayGuard {

    private static final String KEY_PREFIX = "apip:auth:nonce:v1:";
    private static final Duration DEFAULT_TTL = Duration.ofSeconds(660);
    private static final Pattern APP_KEY_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
    private static final Pattern NONCE_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]{16,128}$");

    private final NonceReplayStore store;
    private final Duration ttl;

    public NonceReplayGuard(NonceReplayStore store, Duration ttl) {
        this.store = Objects.requireNonNull(store, "store");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
    }

    public static NonceReplayGuard createDefault(NonceReplayStore store) {
        return new NonceReplayGuard(store, DEFAULT_TTL);
    }

    public void assertUnused(String appKey, String nonce) {
        validate(appKey, nonce);
        String key = key(appKey, nonce);
        boolean claimed;
        try {
            claimed = store.claim(key, ttl);
        } catch (RuntimeException exception) {
            throw failure(
                    "NONCE_STORE_UNAVAILABLE",
                    "Replay protection is unavailable"
            );
        }
        if (!claimed) {
            throw failure("NONCE_REPLAYED", "Nonce has already been used");
        }
    }

    private void validate(String appKey, String nonce) {
        if (appKey == null || !APP_KEY_PATTERN.matcher(appKey).matches()) {
            throw failure("INVALID_REQUEST", "AppKey format is invalid");
        }
        if (nonce == null || !NONCE_PATTERN.matcher(nonce).matches()) {
            throw failure("INVALID_REQUEST", "Nonce format is invalid");
        }
    }

    private String key(String appKey, String nonce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(appKey.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));
            return KEY_PREFIX + toHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private String toHex(byte[] bytes) {
        char[] encoded = new char[bytes.length * 2];
        char[] hex = "0123456789abcdef".toCharArray();
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            encoded[index * 2] = hex[value >>> 4];
            encoded[index * 2 + 1] = hex[value & 0x0f];
        }
        return new String(encoded);
    }

    private HmacVerificationException failure(String code, String message) {
        return new HmacVerificationException(code, message);
    }
}
