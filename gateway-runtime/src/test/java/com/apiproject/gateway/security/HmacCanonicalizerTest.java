package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacCanonicalizerTest {

    private static final byte[] SECRET = bytes(
            "test-secret-0123456789abcdef0123456789abcdef"
    );
    private static final String APP_KEY = "ak_test_1234567890abcdef";
    private static final String TIMESTAMP = "1760000000";
    private static final String NONCE = "abcdefghijklmnop";

    private final HmacCanonicalizer canonicalizer = HmacCanonicalizer.createDefault();

    @Test
    void canonicalizesGetAndProducesGoldenSignature() {
        HmacCanonicalRequest request = new HmacCanonicalRequest(
                APP_KEY,
                "get",
                "API.Example.com:443",
                "/v1/users/%7ealice/",
                "b=2&a=hello%20world&a=1&empty=",
                null,
                1_760_000_000L,
                NONCE,
                bytes("")
        );

        HmacCanonicalResult result = canonicalizer.canonicalize(request, SECRET);

        assertEquals(expectedGetCanonical(), result.canonicalString());
        assertEquals(
                "e984a520a8d177604d6e170765e7ceb5331160bce4c3c8b1ce2f135f8b27c8d7",
                result.signatureHex()
        );
    }

    @Test
    void canonicalizesPostBodyAndContentTypeParameters() {
        HmacCanonicalRequest request = new HmacCanonicalRequest(
                APP_KEY,
                "POST",
                "api.example.com:443",
                "/v1/items/a%3ab/",
                "z=last&tag=x%20y&tag=a",
                "Application/JSON; charset=utf-8",
                1_760_000_123L,
                "nonce_0123456789abcdef",
                bytes("{\"name\":\"张三\",\"active\":true}")
        );

        HmacCanonicalResult result = canonicalizer.canonicalize(request, SECRET);

        assertEquals(expectedPostCanonical(), result.canonicalString());
        assertEquals(
                "471c8f269232b7916932778b02bbaba73cf30e60d4e45e4027a2f4f400cf101c",
                result.signatureHex()
        );
    }

    @Test
    void rejectsRawPlusInQuery() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        requestWithPathAndQuery("/v1/search", "q=a+b"),
                        SECRET
                )
        );

        assertEquals("INVALID_QUERY", exception.code());
    }

    @Test
    void rejectsEncodedSlashInPath() {
        assertInvalidPath("/v1/a%2Fb");
        assertInvalidPath("/v1/a%2fb");
    }

    @Test
    void rejectsDotSegments() {
        assertInvalidPath("/v1/../admin");
        assertInvalidPath("/v1/%2e%2e/admin");
    }

    @Test
    void rejectsConsecutiveSlashes() {
        assertInvalidPath("/v1//users");
    }

    @Test
    void rejectsUnsupportedContentType() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                "POST",
                                "api.example.com",
                                "/v1/items",
                                null,
                                "application/xml",
                                1_760_000_000L,
                                NONCE,
                                bytes("<item/>")
                        ),
                        SECRET
                )
        );

        assertEquals("UNSUPPORTED_CONTENT_TYPE", exception.code());
    }

    @Test
    void rejectsBodyWithoutContentType() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                "POST",
                                "api.example.com",
                                "/v1/items",
                                null,
                                null,
                                1_760_000_000L,
                                NONCE,
                                bytes("{}")
                        ),
                        SECRET
                )
        );

        assertEquals("CONTENT_TYPE_REQUIRED", exception.code());
    }

    @Test
    void rejectsInvalidNonce() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                "GET",
                                "api.example.com",
                                "/v1/users",
                                null,
                                null,
                                1_760_000_000L,
                                "short",
                                bytes("")
                        ),
                        SECRET
                )
        );

        assertEquals("INVALID_NONCE", exception.code());
    }

    @Test
    void rejectsHostWithUserInfo() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                "GET",
                                "user@api.example.com",
                                "/v1/users",
                                null,
                                null,
                                1_760_000_000L,
                                NONCE,
                                bytes("")
                        ),
                        SECRET
                )
        );

        assertEquals("INVALID_HOST", exception.code());
    }

    @Test
    void rejectsShortSecret() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        requestWithPathAndQuery("/v1/users", null),
                        bytes("too-short")
                )
        );

        assertEquals("INVALID_SECRET", exception.code());
    }

    @Test
    void rejectsMethodWithSurroundingWhitespace() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                " GET ",
                                "api.example.com",
                                "/v1/users",
                                null,
                                null,
                                1_760_000_000L,
                                NONCE,
                                bytes("")
                        ),
                        SECRET
                )
        );

        assertEquals("INVALID_METHOD", exception.code());
    }

    @Test
    void rejectsInvalidDnsLabel() {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        new HmacCanonicalRequest(
                                APP_KEY,
                                "GET",
                                "-api.example.com",
                                "/v1/users",
                                null,
                                null,
                                1_760_000_000L,
                                NONCE,
                                bytes("")
                        ),
                        SECRET
                )
        );

        assertEquals("INVALID_HOST", exception.code());
    }

    @Test
    void requestToStringDoesNotExposeReplayOrQueryData() {
        HmacCanonicalRequest request = new HmacCanonicalRequest(
                APP_KEY,
                "GET",
                "api.example.com",
                "/v1/users",
                "token=secret-value",
                null,
                1_760_000_000L,
                NONCE,
                bytes("sensitive-body")
        );

        assertFalse(request.toString().contains("secret-value"));
        assertFalse(request.toString().contains(NONCE));
        assertFalse(request.toString().contains("sensitive-body"));
    }

    @Test
    void resultToStringDoesNotExposeSignature() {
        HmacCanonicalResult result = canonicalizer.canonicalize(
                requestWithPathAndQuery("/v1/users", null),
                SECRET
        );

        assertFalse(result.toString().contains(result.signatureHex()));
        assertFalse(result.toString().contains(result.canonicalString()));
    }

    @ParameterizedTest
    @MethodSource("invalidCanonicalInputs")
    void rejectsInvalidCanonicalInputs(
            HmacCanonicalRequest request,
            String expectedCode
    ) {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(request, SECRET)
        );

        assertEquals(expectedCode, exception.code());
    }

    @Test
    void canonicalizesUnicodePathReservedQueryAndHostPorts() {
        HmacCanonicalRequest request = new HmacCanonicalRequest(
                APP_KEY,
                "GET",
                "[::1]:8443",
                "/v1/用户/%41%7e%3a",
                "q=%26%3d%2b&z=1",
                null,
                1_760_000_000L,
                NONCE,
                bytes("")
        );

        HmacCanonicalResult result = canonicalizer.canonicalize(request, SECRET);
        String[] lines = result.canonicalString().split("\n", -1);

        assertEquals("[::1]:8443", lines[2]);
        assertEquals("/v1/%E7%94%A8%E6%88%B7/A~%3A", lines[4]);
        assertEquals("q=%26%3D%2B&z=1", lines[5]);
    }

    @Test
    void removesDefaultHttpAndHttpsPorts() {
        HmacCanonicalResult http = canonicalizer.canonicalize(
                new HmacCanonicalRequest(
                        APP_KEY,
                        "GET",
                        "api.example.com:80",
                        "/v1/users",
                        null,
                        null,
                        1_760_000_000L,
                        NONCE,
                        bytes("")
                ),
                SECRET
        );
        HmacCanonicalResult https = canonicalizer.canonicalize(
                new HmacCanonicalRequest(
                        APP_KEY,
                        "GET",
                        "api.example.com:443",
                        "/v1/users",
                        null,
                        null,
                        1_760_000_000L,
                        NONCE,
                        bytes("")
                ),
                SECRET
        );

        assertEquals("api.example.com", http.canonicalString().split("\n")[2]);
        assertEquals("api.example.com", https.canonicalString().split("\n")[2]);
    }

    private HmacCanonicalRequest requestWithPathAndQuery(String path, String query) {
        return new HmacCanonicalRequest(
                APP_KEY,
                "GET",
                "api.example.com",
                path,
                query,
                null,
                1_760_000_000L,
                NONCE,
                bytes("")
        );
    }

    private static Stream<Arguments> invalidCanonicalInputs() {
        return Stream.of(
                Arguments.of(request("bad key", "GET", "api.example.com", "/v1/users"),
                        "INVALID_APP_KEY"),
                Arguments.of(request(APP_KEY, "TRACE", "api.example.com", "/v1/users"),
                        "INVALID_METHOD"),
                Arguments.of(request(APP_KEY, "GET", "", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com ", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com/evil", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com:abc", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com:0", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com:65536", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "[::1", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "[::1]x", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "::1", "/v1/users"),
                        "INVALID_HOST"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "v1/users"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users?x"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users#x"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1\\users"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/a b"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/%"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/%zz"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/%00"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/[x]"),
                        "INVALID_PATH"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=1&&b=2"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=1#b"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=1 b"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "=1"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=%"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=%zz"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=%00"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", "a=%E4%B8"),
                        "INVALID_QUERY"),
                Arguments.of(request(APP_KEY, "GET", "api.example.com", "/v1/users", null,
                                null, -1L),
                        "INVALID_TIMESTAMP"),
                Arguments.of(request(APP_KEY, "POST", "api.example.com", "/v1/users", null,
                                " ", 1_760_000_000L),
                        "CONTENT_TYPE_REQUIRED")
        );
    }

    private static HmacCanonicalRequest request(
            String appKey,
            String method,
            String host,
            String path
    ) {
        return request(appKey, method, host, path, null, null, 1_760_000_000L);
    }

    private static HmacCanonicalRequest request(
            String appKey,
            String method,
            String host,
            String path,
            String query
    ) {
        return request(appKey, method, host, path, query, null, 1_760_000_000L);
    }

    private static HmacCanonicalRequest request(
            String appKey,
            String method,
            String host,
            String path,
            String query,
            String contentType,
            long timestamp
    ) {
        byte[] body = contentType == null ? bytes("") : bytes("{}");
        return new HmacCanonicalRequest(
                appKey,
                method,
                host,
                path,
                query,
                contentType,
                timestamp,
                NONCE,
                body
        );
    }

    private void assertInvalidPath(String path) {
        HmacCanonicalizationException exception = assertThrows(
                HmacCanonicalizationException.class,
                () -> canonicalizer.canonicalize(
                        requestWithPathAndQuery(path, null),
                        SECRET
                )
        );

        assertEquals("INVALID_PATH", exception.code(), path);
    }

    private static String expectedGetCanonical() {
        return String.join(
                "\n",
                "AK-HMAC-V1",
                APP_KEY,
                "api.example.com",
                "GET",
                "/v1/users/~alice/",
                "a=1&a=hello%20world&b=2&empty=",
                "",
                TIMESTAMP,
                NONCE,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    private static String expectedPostCanonical() {
        return String.join(
                "\n",
                "AK-HMAC-V1",
                APP_KEY,
                "api.example.com",
                "POST",
                "/v1/items/a%3Ab/",
                "tag=a&tag=x%20y&z=last",
                "application/json",
                "1760000123",
                "nonce_0123456789abcdef",
                "df2e0156744a2063a6c48e43f433a755783c64a8611a3422bf8c94e516e089c1"
        );
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
