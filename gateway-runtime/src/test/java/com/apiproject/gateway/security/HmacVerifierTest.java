package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacVerifierTest {

    private static final byte[] SECRET = bytes(
            "test-secret-0123456789abcdef0123456789abcdef"
    );
    private static final Instant REQUEST_TIME = Instant.ofEpochSecond(1_760_000_000L);

    private final HmacCanonicalizer canonicalizer = HmacCanonicalizer.createDefault();
    private final HmacVerifier verifier = HmacVerifier.createDefault();

    @Test
    void acceptsGoldenSignature() {
        HmacCanonicalRequest request = request();
        String signature = sign(request);

        assertDoesNotThrow(() -> verifier.verify(request, signature, SECRET, REQUEST_TIME));
    }

    @Test
    void acceptsTimestampAtBothBoundaries() {
        HmacCanonicalRequest request = request();
        String signature = sign(request);

        assertDoesNotThrow(() -> verifier.verify(
                request,
                signature,
                SECRET,
                REQUEST_TIME.plusSeconds(300)
        ));
        assertDoesNotThrow(() -> verifier.verify(
                request,
                signature,
                SECRET,
                REQUEST_TIME.minusSeconds(300)
        ));
    }

    @Test
    void rejectsTimestampOutsideWindow() {
        HmacCanonicalRequest request = request();
        String signature = sign(request);

        assertVerificationCode(
                "TIMESTAMP_OUT_OF_WINDOW",
                () -> verifier.verify(request, signature, SECRET, REQUEST_TIME.plusSeconds(301))
        );
        assertVerificationCode(
                "TIMESTAMP_OUT_OF_WINDOW",
                () -> verifier.verify(request, signature, SECRET, REQUEST_TIME.minusSeconds(301))
        );
    }

    @Test
    void rejectsMalformedSignature() {
        HmacCanonicalRequest request = request();

        assertVerificationCode(
                "INVALID_SIGNATURE_FORMAT",
                () -> verifier.verify(request, null, SECRET, REQUEST_TIME)
        );
        assertVerificationCode(
                "INVALID_SIGNATURE_FORMAT",
                () -> verifier.verify(request, "abc", SECRET, REQUEST_TIME)
        );
        assertVerificationCode(
                "INVALID_SIGNATURE_FORMAT",
                () -> verifier.verify(request, "A".repeat(64), SECRET, REQUEST_TIME)
        );
        assertVerificationCode(
                "INVALID_SIGNATURE_FORMAT",
                () -> verifier.verify(request, "z".repeat(64), SECRET, REQUEST_TIME)
        );
    }

    @Test
    void rejectsTamperedBodyAndWrongSecret() {
        HmacCanonicalRequest original = request();
        String signature = sign(original);
        HmacCanonicalRequest tampered = new HmacCanonicalRequest(
                original.appKey(),
                original.method(),
                original.host(),
                original.rawPath(),
                original.rawQuery(),
                original.contentType(),
                original.timestampSeconds(),
                original.nonce(),
                bytes("{\"tampered\":true}")
        );

        assertVerificationCode(
                "INVALID_SIGNATURE",
                () -> verifier.verify(tampered, signature, SECRET, REQUEST_TIME)
        );
        assertVerificationCode(
                "INVALID_SIGNATURE",
                () -> verifier.verify(
                        original,
                        signature,
                        bytes("wrong-secret-0123456789abcdef0123456789abcdef"),
                        REQUEST_TIME
                )
        );
    }

    @Test
    void wrapsInvalidCanonicalRequest() {
        HmacCanonicalRequest request = new HmacCanonicalRequest(
                "ak_test_1234567890abcdef",
                "GET",
                "api.example.com",
                "/v1/../admin",
                null,
                null,
                1_760_000_000L,
                "abcdefghijklmnop",
                bytes("")
        );

        assertVerificationCode(
                "INVALID_REQUEST",
                () -> verifier.verify(request, "0".repeat(64), SECRET, REQUEST_TIME)
        );
    }

    private HmacCanonicalRequest request() {
        return new HmacCanonicalRequest(
                "ak_test_1234567890abcdef",
                "POST",
                "api.example.com",
                "/v1/items",
                "a=1&b=2",
                "application/json",
                1_760_000_000L,
                "abcdefghijklmnop",
                bytes("{\"ok\":true}")
        );
    }

    private String sign(HmacCanonicalRequest request) {
        return canonicalizer.canonicalize(request, SECRET).signatureHex();
    }

    private void assertVerificationCode(
            String code,
            Executable executable
    ) {
        HmacVerificationException exception = assertThrows(
                HmacVerificationException.class,
                executable::execute
        );
        assertEquals(code, exception.code());
    }

    @FunctionalInterface
    private interface Executable {
        void execute() throws Exception;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
