package com.apiproject.gateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ApiProxyFilterTest {

    private static final String REQUEST_ID = "request-123";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void proxiesAllowedRequestAndFiltersHeaders() throws Exception {
        ApiTarget target = new ApiTarget(
                URI.create("https://upstream.example.test/base"),
                "PATCH",
                "/items/{itemId}",
                Duration.ofMillis(1_000)
        );
        AtomicReference<UpstreamRequest> captured = new AtomicReference<>();
        UpstreamClient client = request -> {
            captured.set(request);
            return new UpstreamResponse(
                    201,
                    Map.of(
                            "Content-Type", List.of("application/json"),
                            "Set-Cookie", List.of("unsafe=true"),
                            "ETag", List.of("\"v1\"")
                    ),
                    bytes("{\"accepted\":true}")
            );
        };
        ApiProxyFilter filter = new ApiProxyFilter(
                api -> target,
                client,
                objectMapper
        );
        MockHttpServletRequest request = request(
                "PATCH",
                "/open/v1/items/item-123",
                "mode=full"
        );
        request.setContent(bytes("{\"name\":\"demo\"}"));
        request.setContentType("application/json");
        request.addHeader("Accept", "application/json");
        request.addHeader("Idempotency-Key", "idem-123");
        request.addHeader("X-App-Key", "must-not-forward");
        request.addHeader("X-Signature", "must-not-forward");
        request.addHeader("Cookie", "session=must-not-forward");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNull(chain.getRequest());
        assertEquals(201, response.getStatus());
        assertEquals("application/json", response.getContentType());
        assertEquals("\"v1\"", response.getHeader("ETag"));
        assertNull(response.getHeader("Set-Cookie"));
        assertEquals(REQUEST_ID, response.getHeader("X-Request-Id"));
        assertEquals("{\"accepted\":true}", response.getContentAsString());

        UpstreamRequest upstream = captured.get();
        assertEquals(
                URI.create(
                        "https://upstream.example.test/base/items/item-123"
                                + "?mode=full"
                ),
                upstream.uri()
        );
        assertEquals("PATCH", upstream.method());
        assertEquals(Duration.ofMillis(1_000), upstream.timeout());
        assertEquals("application/json", upstream.headers().get("Accept").get(0));
        assertEquals("idem-123", upstream.headers().get("Idempotency-Key").get(0));
        assertEquals(
                "application/json",
                upstream.headers().get("Content-Type").get(0)
        );
        assertFalse(upstream.headers().containsKey("X-App-Key"));
        assertFalse(upstream.headers().containsKey("X-Signature"));
        assertFalse(upstream.headers().containsKey("Cookie"));
        assertEquals("{\"name\":\"demo\"}", new String(
                upstream.body(),
                StandardCharsets.UTF_8
        ));
    }

    @Test
    void upstreamServerFailureIsNormalizedWithoutLeakingTarget() throws Exception {
        ApiProxyFilter filter = filterReturning(
                new UpstreamResponse(
                        503,
                        Map.of("Content-Type", List.of("text/plain")),
                        bytes("internal upstream address")
                )
        );
        MockHttpServletRequest request = request(
                "GET",
                "/open/v1/items/item-123",
                null
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        JsonNode error = assertError(response, chain, 502, "UPSTREAM_ERROR");
        assertTrue(error.get("retryable").asBoolean());
        assertFalse(response.getContentAsString().contains("upstream.example.test"));
        assertFalse(response.getContentAsString().contains("internal upstream address"));
    }

    @Test
    void timeoutIsMappedToGatewayTimeout() throws Exception {
        ApiProxyFilter filter = new ApiProxyFilter(
                api -> target(),
                request -> {
                    throw new UpstreamClientException(
                            UpstreamClientException.Code.TIMEOUT,
                            "timed out",
                            null
                    );
                },
                objectMapper
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                response,
                chain
        );

        JsonNode error = assertError(
                response,
                chain,
                504,
                "UPSTREAM_TIMEOUT"
        );
        assertTrue(error.get("retryable").asBoolean());
    }

    @Test
    void missingAuthorizedApiFailsClosedBeforeProxy() throws Exception {
        AtomicReference<UpstreamRequest> captured = new AtomicReference<>();
        ApiProxyFilter filter = new ApiProxyFilter(
                api -> target(),
                request -> {
                    captured.set(request);
                    return new UpstreamResponse(200, Map.of(), new byte[0]);
                },
                objectMapper
        );
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET",
                "/open/v1/items/item-123"
        );
        request.setRequestURI("/open/v1/items/item-123");
        request.setAttribute(
                HmacAuthenticationFilter.REQUEST_ID_ATTRIBUTE,
                REQUEST_ID
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertError(
                response,
                chain,
                500,
                "INTERNAL_CONFIGURATION"
        );
        assertNull(captured.get());
    }

    @Test
    void routeExpansionFailureFailsAsUpstreamError() throws Exception {
        ApiProxyFilter filter = new ApiProxyFilter(
                api -> new ApiTarget(
                        URI.create("https://upstream.example.test"),
                        "GET",
                        "/items/{missing}",
                        Duration.ofSeconds(1)
                ),
                upstream -> {
                    throw new AssertionError("upstream must not run");
                },
                objectMapper
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                response,
                chain
        );

        JsonNode error = assertError(response, chain, 502, "UPSTREAM_ERROR");
        assertFalse(error.get("retryable").asBoolean());
    }

    @Test
    void nonPublicAndNonHttpRequestsPassThrough() throws Exception {
        ApiProxyFilter filter = filterReturning(
                new UpstreamResponse(200, Map.of(), new byte[0])
        );
        MockHttpServletRequest nonPublic = new MockHttpServletRequest(
                "GET",
                "/platform-admin/v1/apis"
        );
        nonPublic.setRequestURI("/platform-admin/v1/apis");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(nonPublic, response, chain);

        assertEquals(nonPublic, chain.getRequest());

        ServletRequest nonHttpRequest = mock(ServletRequest.class);
        ServletResponse nonHttpResponse = mock(ServletResponse.class);
        FilterChain nonHttpChain = mock(FilterChain.class);
        filter.doFilter(
                nonHttpRequest,
                nonHttpResponse,
                nonHttpChain
        );
        verify(nonHttpChain).doFilter(nonHttpRequest, nonHttpResponse);
    }

    @Test
    void missingRequestIdIsGeneratedAndUpstreamClientErrorsAreMapped()
            throws Exception {
        ApiProxyFilter targetFailure = new ApiProxyFilter(
                api -> {
                    throw new ApiTargetResolutionException(
                            "UPSTREAM_CONFIGURATION_ERROR",
                            false,
                            "invalid",
                            null
                    );
                },
                upstream -> {
                    throw new AssertionError("upstream must not run");
                },
                objectMapper
        );
        MockHttpServletRequest request = request(
                "GET",
                "/open/v1/items/item-123",
                null
        );
        request.removeAttribute(HmacAuthenticationFilter.REQUEST_ID_ATTRIBUTE);
        MockHttpServletResponse targetResponse = new MockHttpServletResponse();
        MockFilterChain targetChain = new MockFilterChain();

        targetFailure.doFilter(request, targetResponse, targetChain);

        assertTrue(targetResponse.getHeader("X-Request-Id") != null);
        assertEquals(502, targetResponse.getStatus());

        ApiProxyFilter targetUnavailable = new ApiProxyFilter(
                api -> {
                    throw new ApiTargetResolutionException(
                            "TARGET_STORE_UNAVAILABLE",
                            true,
                            "database down",
                            null
                    );
                },
                upstream -> {
                    throw new AssertionError("upstream must not run");
                },
                objectMapper
        );
        MockHttpServletResponse unavailableResponse =
                new MockHttpServletResponse();
        MockFilterChain unavailableChain = new MockFilterChain();
        targetUnavailable.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                unavailableResponse,
                unavailableChain
        );
        JsonNode unavailableError = assertError(
                unavailableResponse,
                unavailableChain,
                503,
                "TARGET_STORE_UNAVAILABLE"
        );
        assertTrue(unavailableError.get("retryable").asBoolean());

        ApiProxyFilter transportFailure = new ApiProxyFilter(
                api -> target(),
                upstream -> {
                    throw new UpstreamClientException(
                            UpstreamClientException.Code.TRANSPORT,
                            "transport",
                            null
                    );
                },
                objectMapper
        );
        MockHttpServletResponse transportResponse = new MockHttpServletResponse();
        MockFilterChain transportChain = new MockFilterChain();
        transportFailure.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                transportResponse,
                transportChain
        );
        assertError(
                transportResponse,
                transportChain,
                502,
                "UPSTREAM_ERROR"
        );

        ApiProxyFilter tooLarge = new ApiProxyFilter(
                api -> target(),
                upstream -> {
                    throw new UpstreamClientException(
                            UpstreamClientException.Code.RESPONSE_TOO_LARGE,
                            "large",
                            null
                    );
                },
                objectMapper
        );
        MockHttpServletResponse largeResponse = new MockHttpServletResponse();
        MockFilterChain largeChain = new MockFilterChain();
        tooLarge.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                largeResponse,
                largeChain
        );
        JsonNode largeError = assertError(
                largeResponse,
                largeChain,
                502,
                "UPSTREAM_ERROR"
        );
        assertFalse(largeError.get("retryable").asBoolean());
    }

    @Test
    void upstreamClientErrorsMapToServerErrorAndFourXxPassesThrough()
            throws Exception {
        ApiProxyFilter unexpected = new ApiProxyFilter(
                api -> target(),
                upstream -> {
                    throw new IllegalStateException("unexpected");
                },
                objectMapper
        );
        MockHttpServletResponse unexpectedResponse = new MockHttpServletResponse();
        MockFilterChain unexpectedChain = new MockFilterChain();
        unexpected.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                unexpectedResponse,
                unexpectedChain
        );
        assertError(
                unexpectedResponse,
                unexpectedChain,
                500,
                "INTERNAL_ERROR"
        );

        ApiProxyFilter passThrough = filterReturning(
                new UpstreamResponse(
                        404,
                        Map.of("Content-Type", List.of("application/json")),
                        bytes("{\"upstream\":\"missing\"}")
                )
        );
        MockHttpServletResponse passResponse = new MockHttpServletResponse();
        MockFilterChain passChain = new MockFilterChain();
        passThrough.doFilter(
                request("GET", "/open/v1/items/item-123", null),
                passResponse,
                passChain
        );

        assertNull(passChain.getRequest());
        assertEquals(404, passResponse.getStatus());
        assertEquals("{\"upstream\":\"missing\"}", passResponse.getContentAsString());
    }

    @Test
    void oversizedBodyAndWrongAuthorizedAttributeFailClosed()
            throws Exception {
        ApiProxyFilter filter = new ApiProxyFilter(
                api -> target(),
                request -> {
                    throw new AssertionError("upstream must not run");
                },
                objectMapper
        );
        MockHttpServletRequest oversized = request(
                "POST",
                "/open/v1/items/item-123",
                null
        );
        oversized.setContent(new byte[HmacAuthenticationFilter.MAX_BODY_BYTES + 1]);
        MockHttpServletResponse oversizedResponse = new MockHttpServletResponse();
        MockFilterChain oversizedChain = new MockFilterChain();

        filter.doFilter(oversized, oversizedResponse, oversizedChain);

        assertError(
                oversizedResponse,
                oversizedChain,
                413,
                "REQUEST_TOO_LARGE"
        );

        MockHttpServletRequest wrongAttribute = request(
                "GET",
                "/open/v1/items/item-123",
                null
        );
        wrongAttribute.setAttribute(
                HmacAuthenticationFilter.AUTHORIZED_API_ATTRIBUTE,
                "wrong-type"
        );
        MockHttpServletResponse wrongResponse = new MockHttpServletResponse();
        MockFilterChain wrongChain = new MockFilterChain();

        filter.doFilter(wrongAttribute, wrongResponse, wrongChain);

        assertError(
                wrongResponse,
                wrongChain,
                500,
                "INTERNAL_CONFIGURATION"
        );
    }

    private ApiProxyFilter filterReturning(UpstreamResponse upstreamResponse) {
        return new ApiProxyFilter(
                api -> target(),
                request -> upstreamResponse,
                objectMapper
        );
    }

    private ApiTarget target() {
        return new ApiTarget(
                URI.create("https://upstream.example.test"),
                "GET",
                "/items/{itemId}",
                Duration.ofSeconds(1)
        );
    }

    private MockHttpServletRequest request(
            String method,
            String path,
            String query
    ) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        request.setQueryString(query);
        request.setAttribute(
                HmacAuthenticationFilter.AUTHORIZED_API_ATTRIBUTE,
                new AuthorizedApi(
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        "PLATFORM_PUBLIC",
                        Map.of("itemId", "item-123")
                )
        );
        request.setAttribute(
                HmacAuthenticationFilter.REQUEST_ID_ATTRIBUTE,
                REQUEST_ID
        );
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
        JsonNode error = objectMapper.readTree(response.getContentAsByteArray());
        assertEquals(code, error.get("code").asText());
        assertEquals(REQUEST_ID, error.get("requestId").asText());
        return error;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
