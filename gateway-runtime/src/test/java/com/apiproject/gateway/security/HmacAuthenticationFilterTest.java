package com.apiproject.gateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacAuthenticationFilterTest {

    private static final String APP_KEY = "ak_test_1234567890abcdef";
    private static final String NONCE = "abcdefghijklmnop";
    private static final long TIMESTAMP = 1_760_000_000L;
    private static final Instant NOW = Instant.ofEpochSecond(TIMESTAMP);
    private static final byte[] SECRET = bytes(
            "test-secret-0123456789abcdef0123456789abcdef"
    );

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HmacCanonicalizer canonicalizer = HmacCanonicalizer.createDefault();

    private RecordingNonceStore nonceStore;
    private HmacAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        nonceStore = new RecordingNonceStore();
        filter = filterWithResolver(
                nonceStore,
                appKey -> APP_KEY.equals(appKey) ? Optional.of(SECRET.clone()) : Optional.empty()
        );
    }

    @Test
    void authenticatesRequestAndPreservesCachedBodyForDownstream() throws Exception {
        byte[] body = bytes("{\"orderId\":\"A-1\"}");
        MockHttpServletRequest request = signedRequest(
                "POST",
                "/open/v1/orders",
                "trace=1",
                body,
                "application/json",
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
        assertEquals(
                APP_KEY,
                chain.getRequest().getAttribute(
                        HmacAuthenticationFilter.AUTHENTICATED_APP_KEY_ATTRIBUTE
                )
        );
        AuthorizedApi authorizedApi = (AuthorizedApi) chain.getRequest().getAttribute(
                HmacAuthenticationFilter.AUTHORIZED_API_ATTRIBUTE
        );
        assertNotNull(authorizedApi);
        assertEquals(UUID.fromString("00000000-0000-0000-0000-000000000001"),
                authorizedApi.apiId());
        assertNotNull(response.getHeader("X-Request-Id"));
        assertArrayEquals(
                body,
                ((jakarta.servlet.http.HttpServletRequest) chain.getRequest())
                        .getInputStream()
                        .readAllBytes()
        );
    }

    @Test
    void invalidSignatureReturns401AndDoesNotRunDownstream() throws Exception {
        MockHttpServletRequest request = baseRequest("GET", "/open/v1/orders");
        request.addHeader("X-Nonce", NONCE);
        request.addHeader("X-Timestamp", Long.toString(TIMESTAMP));
        request.addHeader("X-Signature", "0".repeat(64));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 401, "INVALID_SIGNATURE");
    }

    @Test
    void staleTimestampReturns401AndDoesNotRunDownstream() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        HmacAuthenticationFilter staleFilter = new HmacAuthenticationFilter(
                appKey -> Optional.of(SECRET.clone()),
                authenticator(nonceStore),
                objectMapper,
                Clock.fixed(NOW.plusSeconds(301), ZoneOffset.UTC),
                allowingAuthorizationGate(),
                allowingRateLimiter(),
                allowingPostAuthLimitGate()
        );
        staleFilter.doFilter(request, response, chain);

        assertError(response, chain, 401, "TIMESTAMP_OUT_OF_WINDOW");
    }

    @Test
    void malformedTimestampReturns400() throws Exception {
        MockHttpServletRequest request = baseRequest("GET", "/open/v1/orders");
        request.addHeader("X-Nonce", NONCE);
        request.addHeader("X-Timestamp", "not-a-timestamp");
        request.addHeader("X-Signature", "0".repeat(64));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "INVALID_TIMESTAMP_FORMAT");
    }

    @Test
    void unsupportedSignatureVersionReturns400() throws Exception {
        MockHttpServletRequest request = bareRequest("GET", "/open/v1/orders");
        request.addHeader("X-Signature-Version", "v2");
        request.addHeader("X-App-Key", APP_KEY);
        request.addHeader("X-Nonce", NONCE);
        request.addHeader("X-Timestamp", Long.toString(TIMESTAMP));
        request.addHeader("X-Signature", "0".repeat(64));

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "UNSUPPORTED_SIGNATURE_VERSION");
    }

    @Test
    void missingAuthHeaderReturns401() throws Exception {
        MockHttpServletRequest request = bareRequest("GET", "/open/v1/orders");
        request.addHeader("X-Signature-Version", "v1");
        request.addHeader("X-Nonce", NONCE);
        request.addHeader("X-Timestamp", Long.toString(TIMESTAMP));
        request.addHeader("X-Signature", "0".repeat(64));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 401, "MISSING_AUTH_HEADER");
    }

    @Test
    void duplicateHeaderReturns400() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        request.addHeader("X-Nonce", "secondnonce123456");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "DUPLICATE_HEADER");
    }

    @Test
    void duplicateContentLengthReturns400() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        request.addHeader("Content-Length", "0");
        request.addHeader("Content-Length", "0");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "DUPLICATE_HEADER");
    }

    @Test
    void unknownCredentialReturns401WithoutSecretLeak() throws Exception {
        filter = filterWithResolver(nonceStore, appKey -> Optional.empty());
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 401, "INVALID_CREDENTIAL");
        assertFalse(response.getContentAsString().contains("secret"));
    }

    @Test
    void replayReturns401() throws Exception {
        MockHttpServletRequest first = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        MockFilterChain firstChain = new MockFilterChain();
        filter.doFilter(first, firstResponse, firstChain);

        MockHttpServletRequest second = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse secondResponse = new MockHttpServletResponse();
        MockFilterChain secondChain = new MockFilterChain();
        filter.doFilter(second, secondResponse, secondChain);

        assertError(secondResponse, secondChain, 401, "NONCE_REPLAYED");
    }

    @Test
    void unavailableNonceStoreReturns503AndIsRetryable() throws Exception {
        filter = filterWithResolver(
                (key, ttl) -> {
                    throw new IllegalStateException("redis down");
                },
                appKey -> Optional.of(SECRET.clone())
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "NONCE_STORE_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
    }

    @Test
    void oversizedBodyReturns413BeforeDownstream() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "POST",
                "/open/v1/orders",
                null,
                bytes("{}"),
                "application/json",
                NONCE,
                TIMESTAMP
        );
        request.addHeader(
                "Content-Length",
                Integer.toString(HmacAuthenticationFilter.MAX_BODY_BYTES + 1)
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 413, "REQUEST_TOO_LARGE");
    }

    @Test
    void streamingBodyLimitAppliesWithoutDeclaredContentLength() throws Exception {
        byte[] body = new byte[HmacAuthenticationFilter.MAX_BODY_BYTES + 1];
        MockHttpServletRequest request = signedRequest(
                "POST",
                "/open/v1/orders",
                null,
                body,
                "application/json",
                NONCE,
                TIMESTAMP
        );
        request.removeHeader("Content-Length");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 413, "REQUEST_TOO_LARGE");
    }

    @Test
    void negativeContentLengthReturns400() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        request.addHeader("Content-Length", "-1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "INVALID_CONTENT_LENGTH");
    }

    @Test
    void unavailableCredentialStoreReturns503AndIsRetryable() throws Exception {
        filter = filterWithResolver(nonceStore, appKey -> {
            throw new IllegalStateException("credential database down");
        });
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "CREDENTIAL_STORE_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
    }

    @Test
    void invalidStoredSecretReturns500WithoutLeakingInternals() throws Exception {
        filter = filterWithResolver(nonceStore, appKey -> Optional.of(new byte[0]));
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                500,
                "INTERNAL_CONFIGURATION"
        );
        assertFalse(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("secret"));
    }

    @Test
    void typedInternalCredentialFailureReturns500WithoutLeakingDetails() throws Exception {
        filter = filterWithResolver(nonceStore, appKey -> {
            throw new CredentialResolutionException(
                    "INTERNAL_CONFIGURATION",
                    false,
                    "kms decryption failed",
                    null
            );
        });
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                500,
                "INTERNAL_CONFIGURATION"
        );
        assertFalse(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("decryption"));
    }

    @Test
    void typedCredentialStoreFailureReturnsRetryable503() throws Exception {
        filter = filterWithResolver(nonceStore, appKey -> {
            throw new CredentialResolutionException(
                    "CREDENTIAL_STORE_UNAVAILABLE",
                    true,
                    "database unavailable",
                    null
            );
        });
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "CREDENTIAL_STORE_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("database"));
    }

    @Test
    void exactPublicApiPathIsProtected() throws Exception {
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
    }

    @Test
    void cachedBodyReaderPreservesDeclaredCharsetAndLength() throws Exception {
        byte[] body = "caf\u00e9".getBytes(StandardCharsets.ISO_8859_1);
        MockHttpServletRequest request = signedRequest(
                "POST",
                "/open/v1/orders",
                null,
                body,
                "text/plain;charset=ISO-8859-1",
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        jakarta.servlet.http.HttpServletRequest downstream =
                (jakarta.servlet.http.HttpServletRequest) chain.getRequest();
        assertEquals("caf\u00e9", downstream.getReader().readLine());
        assertEquals(body.length, downstream.getContentLength());
        assertEquals(body.length, downstream.getContentLengthLong());
    }

    @Test
    void cachedBodyReaderDefaultsToUtf8WithoutDeclaredCharset() throws Exception {
        byte[] body = "\u4e2d\u6587".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = signedRequest(
                "POST",
                "/open/v1/orders",
                null,
                body,
                "application/json",
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        jakarta.servlet.http.HttpServletRequest downstream =
                (jakarta.servlet.http.HttpServletRequest) chain.getRequest();
        assertEquals("\u4e2d\u6587", downstream.getReader().readLine());
    }

    @Test
    void malformedCanonicalRequestReturns400() throws Exception {
        MockHttpServletRequest request = baseRequest("GET", "/open/v1/%2Fadmin");
        request.addHeader("X-Nonce", NONCE);
        request.addHeader("X-Timestamp", Long.toString(TIMESTAMP));
        request.addHeader("X-Signature", "0".repeat(64));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 400, "INVALID_REQUEST");
    }

    @Test
    void nonPublicPathBypassesFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET",
                "/platform-admin/v1/tenants"
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertNull(response.getHeader("X-Request-Id"));
    }

    @Test
    void apiWithoutGrantReturns403() throws Exception {
        filter = filterWithResolver(
                nonceStore,
                appKey -> Optional.of(SECRET.clone()),
                (appKey, method, path) -> {
                    throw new ApiAuthorizationException(
                            "API_NOT_GRANTED",
                            false,
                            "missing grant",
                            null
                    );
                }
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 403, "API_NOT_GRANTED");
    }

    @Test
    void unknownPublishedApiReturns404() throws Exception {
        filter = filterWithResolver(
                nonceStore,
                appKey -> Optional.of(SECRET.clone()),
                (appKey, method, path) -> {
                    throw new ApiAuthorizationException(
                            "API_NOT_FOUND",
                            false,
                            "missing api",
                            null
                    );
                }
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 404, "API_NOT_FOUND");
    }

    @Test
    void authorizationStoreFailureReturnsRetryable503() throws Exception {
        filter = filterWithResolver(
                nonceStore,
                appKey -> Optional.of(SECRET.clone()),
                (appKey, method, path) -> {
                    throw new ApiAuthorizationException(
                            "AUTHORIZATION_STORE_UNAVAILABLE",
                            true,
                            "database down",
                            null
                    );
                }
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "AUTHORIZATION_STORE_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("database"));
    }

    @Test
    void rateLimitDeniedBeforeAuthenticationReturns429() throws Exception {
        filter = new HmacAuthenticationFilter(
                appKey -> {
                    throw new AssertionError("credential resolver must not run");
                },
                authenticator(nonceStore),
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC),
                allowingAuthorizationGate(),
                clientAddress -> new RateLimitDecision(
                        false,
                        10,
                        0,
                        42
                ),
                allowingPostAuthLimitGate()
        );
        MockHttpServletRequest request = bareRequest("GET", "/open/v1/orders");
        request.setRemoteAddr("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(response, chain, 429, "RATE_LIMITED");
        assertTrue(error.get("retryable").asBoolean());
        assertEquals("42", response.getHeader("Retry-After"));
        assertEquals("10", response.getHeader("X-RateLimit-Limit"));
        assertEquals("0", response.getHeader("X-RateLimit-Remaining"));
    }

    @Test
    void rateLimitStoreFailureReturnsRetryable503() throws Exception {
        filter = new HmacAuthenticationFilter(
                appKey -> Optional.of(SECRET.clone()),
                authenticator(nonceStore),
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC),
                allowingAuthorizationGate(),
                clientAddress -> {
                    throw new PreAuthRateLimitException(
                            "RATE_LIMIT_UNAVAILABLE",
                            true,
                            "redis down",
                            null
                    );
                },
                allowingPostAuthLimitGate()
        );
        MockHttpServletRequest request = baseRequest("GET", "/open/v1/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "RATE_LIMIT_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("redis"));
    }

    @Test
    void postAuthRateLimitDeniedAfterAuthorizationReturns429() throws Exception {
        filter = filterWithPostAuthGate(
                api -> new PostAuthRateLimitDecision(
                        false,
                        "RATE_LIMITED",
                        20,
                        0,
                        30,
                        2
                )
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(response, chain, 429, "RATE_LIMITED");
        assertTrue(error.get("retryable").asBoolean());
        assertEquals("20", response.getHeader("X-RateLimit-Limit"));
        assertEquals("0", response.getHeader("X-RateLimit-Remaining"));
        assertEquals("2", response.getHeader("Retry-After"));
    }

    @Test
    void postAuthQuotaDeniedAfterAuthorizationReturns429() throws Exception {
        filter = filterWithPostAuthGate(
                api -> new PostAuthRateLimitDecision(
                        false,
                        "QUOTA_EXCEEDED",
                        1_000,
                        0,
                        3_600,
                        3_600
                )
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(response, chain, 429, "QUOTA_EXCEEDED");
        assertEquals("1000", response.getHeader("X-RateLimit-Limit"));
        assertEquals("3600", response.getHeader("Retry-After"));
    }

    @Test
    void postAuthLimitStoreFailureReturnsRetryable503() throws Exception {
        filter = filterWithPostAuthGate(api -> {
            throw new PostAuthRateLimitException(
                    "RATE_LIMIT_UNAVAILABLE",
                    true,
                    "post-auth redis down",
                    null
            );
        });
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(
                response,
                chain,
                503,
                "RATE_LIMIT_UNAVAILABLE"
        );
        assertTrue(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("post-auth redis down"));
    }

    @Test
    void resolverSecretIsWipedAfterAuthentication() throws Exception {
        byte[] resolvedSecret = SECRET.clone();
        filter = filterWithResolver(
                nonceStore,
                appKey -> Optional.of(resolvedSecret)
        );
        MockHttpServletRequest request = signedRequest(
                "GET",
                "/open/v1/orders",
                null,
                bytes(""),
                null,
                NONCE,
                TIMESTAMP
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertArrayEquals(new byte[resolvedSecret.length], resolvedSecret);
    }

    private HmacAuthenticationFilter filterWithResolver(
            NonceReplayStore nonceStore,
            ActiveCredentialResolver resolver
    ) {
        return filterWithResolver(
                nonceStore,
                resolver,
                allowingAuthorizationGate()
        );
    }

    private HmacAuthenticationFilter filterWithResolver(
            NonceReplayStore nonceStore,
            ActiveCredentialResolver resolver,
            ApiAuthorizationGate authorizationGate
    ) {
        return new HmacAuthenticationFilter(
                resolver,
                authenticator(nonceStore),
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC),
                authorizationGate,
                allowingRateLimiter(),
                allowingPostAuthLimitGate()
        );
    }

    private HmacAuthenticationFilter filterWithPostAuthGate(
            PostAuthLimitGate postAuthLimitGate
    ) {
        return new HmacAuthenticationFilter(
                appKey -> Optional.of(SECRET.clone()),
                authenticator(nonceStore),
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC),
                allowingAuthorizationGate(),
                allowingRateLimiter(),
                postAuthLimitGate
        );
    }

    private ApiAuthorizationGate allowingAuthorizationGate() {
        return (appKey, method, path) -> new AuthorizedApi(
                UUID.fromString("00000000-0000-0000-0000-000000000004"),
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                UUID.fromString("00000000-0000-0000-0000-000000000002"),
                UUID.fromString("00000000-0000-0000-0000-000000000003"),
                "PLATFORM_PUBLIC"
        );
    }

    private PreAuthRateLimiter allowingRateLimiter() {
        return clientAddress -> new RateLimitDecision(
                true,
                120,
                119,
                60
        );
    }

    private PostAuthLimitGate allowingPostAuthLimitGate() {
        return api -> new PostAuthRateLimitDecision(
                true,
                null,
                120,
                119,
                60,
                0
        );
    }

    private HmacRequestAuthenticator authenticator(NonceReplayStore nonceStore) {
        return new HmacRequestAuthenticator(
                HmacVerifier.createDefault(),
                NonceReplayGuard.createDefault(nonceStore)
        );
    }

    private MockHttpServletRequest signedRequest(
            String method,
            String path,
            String query,
            byte[] body,
            String contentType,
            String nonce,
            long timestamp
    ) {
        MockHttpServletRequest request = baseRequest(method, path, query, body, contentType);
        request.addHeader("X-Nonce", nonce);
        request.addHeader("X-Timestamp", Long.toString(timestamp));
        HmacCanonicalRequest canonicalRequest = new HmacCanonicalRequest(
                APP_KEY,
                method,
                "api.example.com",
                path,
                query,
                contentType,
                timestamp,
                nonce,
                body
        );
        request.addHeader(
                "X-Signature",
                canonicalizer.canonicalize(canonicalRequest, SECRET).signatureHex()
        );
        return request;
    }

    private MockHttpServletRequest baseRequest(String method, String path) {
        return baseRequest(method, path, null, bytes(""), null);
    }

    private MockHttpServletRequest bareRequest(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        request.addHeader("Host", "api.example.com");
        return request;
    }

    private MockHttpServletRequest baseRequest(
            String method,
            String path,
            String query,
            byte[] body,
            String contentType
    ) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        request.setQueryString(query);
        request.setContent(body);
        request.addHeader("Host", "api.example.com");
        request.addHeader("X-Signature-Version", "v1");
        request.addHeader("X-App-Key", APP_KEY);
        if (contentType != null) {
            request.setContentType(contentType);
        }
        return request;
    }

    private JsonNode assertError(
            MockHttpServletResponse response,
            MockFilterChain chain,
            int status,
            String code
    ) throws Exception {
        assertEquals(status, response.getStatus());
        assertNull(chain.getRequest());
        assertTrue(response.getContentType().startsWith("application/json"));
        assertNotNull(response.getHeader("X-Request-Id"));
        JsonNode error = objectMapper.readTree(response.getContentAsByteArray());
        assertEquals(code, error.get("code").asText());
        assertEquals(
                response.getHeader("X-Request-Id"),
                error.get("requestId").asText()
        );
        return error;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static final class RecordingNonceStore implements NonceReplayStore {
        private final Set<String> keys = new HashSet<>();

        @Override
        public boolean claim(String key, Duration ttl) {
            return keys.add(key);
        }
    }
}
