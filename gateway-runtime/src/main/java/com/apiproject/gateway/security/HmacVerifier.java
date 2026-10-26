package com.apiproject.gateway.security;

import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;

public final class HmacVerifier {

    private static final Duration DEFAULT_MAX_SKEW = Duration.ofSeconds(300);
    private static final Pattern SIGNATURE_PATTERN =
            Pattern.compile("^[0-9a-f]{64}$");

    private final HmacCanonicalizer canonicalizer;
    private final Duration maxSkew;

    public HmacVerifier(HmacCanonicalizer canonicalizer, Duration maxSkew) {
        this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
        this.maxSkew = Objects.requireNonNull(maxSkew, "maxSkew");
        if (maxSkew.isNegative() || maxSkew.isZero()) {
            throw new IllegalArgumentException("maxSkew must be positive");
        }
    }

    public static HmacVerifier createDefault() {
        return new HmacVerifier(HmacCanonicalizer.createDefault(), DEFAULT_MAX_SKEW);
    }

    public void verify(
            HmacCanonicalRequest request,
            String signatureHex,
            byte[] secret,
            Instant receivedAt
    ) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(receivedAt, "receivedAt");
        if (signatureHex == null || !SIGNATURE_PATTERN.matcher(signatureHex).matches()) {
            throw failure(
                    "INVALID_SIGNATURE_FORMAT",
                    "Signature must be 64 lowercase hexadecimal characters"
            );
        }

        verifyTimestamp(request.timestampSeconds(), receivedAt);

        HmacCanonicalResult expected;
        try {
            expected = canonicalizer.canonicalize(request, secret);
        } catch (HmacCanonicalizationException exception) {
            String code = "INVALID_SECRET".equals(exception.code())
                    ? "INTERNAL_CONFIGURATION"
                    : "INVALID_REQUEST";
            throw failure(code, "Request cannot be canonicalized");
        }

        byte[] provided = HexFormat.of().parseHex(signatureHex);
        byte[] calculated = HexFormat.of().parseHex(expected.signatureHex());
        if (!MessageDigest.isEqual(provided, calculated)) {
            throw failure("INVALID_SIGNATURE", "Signature verification failed");
        }
    }

    private void verifyTimestamp(long timestampSeconds, Instant receivedAt) {
        try {
            Duration difference = Duration.between(
                    Instant.ofEpochSecond(timestampSeconds),
                    receivedAt
            ).abs();
            if (difference.compareTo(maxSkew) > 0) {
                throw failure(
                        "TIMESTAMP_OUT_OF_WINDOW",
                        "Request timestamp is outside the allowed window"
                );
            }
        } catch (DateTimeException | ArithmeticException exception) {
            throw failure(
                    "TIMESTAMP_OUT_OF_WINDOW",
                    "Request timestamp is outside the allowed window"
            );
        }
    }

    private HmacVerificationException failure(String code, String message) {
        return new HmacVerificationException(code, message);
    }
}
