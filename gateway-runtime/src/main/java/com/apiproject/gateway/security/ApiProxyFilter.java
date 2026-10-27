package com.apiproject.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public final class ApiProxyFilter implements Filter {

    private static final List<String> REQUEST_HEADERS = List.of(
            "Accept",
            "Content-Type",
            "Idempotency-Key",
            "User-Agent",
            "X-Client-Request-Id"
    );
    private static final Set<String> RESPONSE_HEADERS = Set.of(
            "cache-control",
            "content-disposition",
            "content-type",
            "etag",
            "last-modified",
            "location",
            "retry-after"
    );

    private final ApiTargetResolver targetResolver;
    private final UpstreamClient upstreamClient;
    private final ObjectMapper objectMapper;

    public ApiProxyFilter(
            ApiTargetResolver targetResolver,
            UpstreamClient upstreamClient,
            ObjectMapper objectMapper
    ) {
        this.targetResolver = Objects.requireNonNull(
                targetResolver,
                "targetResolver"
        );
        this.upstreamClient = Objects.requireNonNull(
                upstreamClient,
                "upstreamClient"
        );
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // No initialization required.
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain chain
    ) throws IOException, ServletException {
        if (!(servletRequest instanceof HttpServletRequest request)
                || !(servletResponse instanceof HttpServletResponse response)) {
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (!isPublicApiPath(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        Object requestIdAttribute = request.getAttribute(
                HmacAuthenticationFilter.REQUEST_ID_ATTRIBUTE
        );
        String requestId = requestIdAttribute instanceof String value
                && !value.isBlank()
                ? value
                : null;
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        Object authorizedApiAttribute = request.getAttribute(
                HmacAuthenticationFilter.AUTHORIZED_API_ATTRIBUTE
        );
        if (!(authorizedApiAttribute instanceof AuthorizedApi authorizedApi)) {
            writeError(
                    response,
                    requestId,
                    500,
                    "INTERNAL_CONFIGURATION",
                    false
            );
            return;
        }

        try {
            ApiTarget target = targetResolver.resolve(authorizedApi);
            URI upstreamUri = buildUpstreamUri(request, target, authorizedApi);
            byte[] body = readBody(request);
            UpstreamResponse upstream = upstreamClient.execute(
                    new UpstreamRequest(
                            upstreamUri,
                            target.method(),
                            forwardedHeaders(request),
                            body,
                            target.timeout()
                    )
            );
            if (upstream.status() >= 500) {
                writeError(response, requestId, 502, "UPSTREAM_ERROR", true);
                return;
            }
            writeUpstreamResponse(response, requestId, upstream);
        } catch (ApiTargetResolutionException exception) {
            if (exception.retryable()) {
                writeError(
                        response,
                        requestId,
                        503,
                        exception.code(),
                        true
                );
            } else {
                writeError(response, requestId, 502, "UPSTREAM_ERROR", false);
            }
        } catch (UpstreamClientException exception) {
            mapUpstreamFailure(response, requestId, exception);
        } catch (RequestTooLargeException exception) {
            writeError(response, requestId, 413, "REQUEST_TOO_LARGE", false);
        } catch (IllegalArgumentException exception) {
            writeError(response, requestId, 502, "UPSTREAM_ERROR", false);
        } catch (IOException exception) {
            writeError(response, requestId, 400, "REQUEST_READ_FAILED", false);
        } catch (RuntimeException exception) {
            writeError(response, requestId, 500, "INTERNAL_ERROR", false);
        }
    }

    private URI buildUpstreamUri(
            HttpServletRequest request,
            ApiTarget target,
            AuthorizedApi authorizedApi
    ) {
        String upstreamPath = RouteTemplateExpander.expand(
                target.pathTemplate(),
                authorizedApi.routeParameters()
        );
        String basePath = target.baseUri().getRawPath();
        if (basePath == null || basePath.isEmpty() || "/".equals(basePath)) {
            basePath = "";
        } else if (basePath.endsWith("/")) {
            basePath = basePath.substring(0, basePath.length() - 1);
        }
        String path = basePath + upstreamPath;
        String query = request.getQueryString();
        String value = target.baseUri().getScheme()
                + "://"
                + target.baseUri().getRawAuthority()
                + path
                + (query == null || query.isEmpty() ? "" : "?" + query);
        return URI.create(value);
    }

    private Map<String, List<String>> forwardedHeaders(
            HttpServletRequest request
    ) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String name : REQUEST_HEADERS) {
            List<String> values = Collections.list(request.getHeaders(name));
            if (!values.isEmpty()) {
                headers.put(name, List.copyOf(values));
            }
        }
        return headers;
    }

    private byte[] readBody(HttpServletRequest request) throws IOException {
        byte[] body = request.getInputStream().readNBytes(
                HmacAuthenticationFilter.MAX_BODY_BYTES + 1
        );
        if (body.length > HmacAuthenticationFilter.MAX_BODY_BYTES) {
            throw new RequestTooLargeException();
        }
        return body;
    }

    private void writeUpstreamResponse(
            HttpServletResponse response,
            String requestId,
            UpstreamResponse upstream
    ) throws IOException {
        response.setStatus(upstream.status());
        upstream.headers().forEach((name, values) -> {
            if (RESPONSE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                values.forEach(value -> response.addHeader(name, value));
            }
        });
        response.setHeader("X-Request-Id", requestId);
        byte[] body = upstream.body();
        if (body.length > 0) {
            response.getOutputStream().write(body);
        }
    }

    private void mapUpstreamFailure(
            HttpServletResponse response,
            String requestId,
            UpstreamClientException exception
    ) throws IOException {
        switch (exception.code()) {
            case TIMEOUT -> writeError(
                    response,
                    requestId,
                    504,
                    "UPSTREAM_TIMEOUT",
                    true
            );
            case RESPONSE_TOO_LARGE -> writeError(
                    response,
                    requestId,
                    502,
                    "UPSTREAM_ERROR",
                    false
            );
            case TRANSPORT -> writeError(
                    response,
                    requestId,
                    502,
                    "UPSTREAM_ERROR",
                    true
            );
        }
    }

    private void writeError(
            HttpServletResponse response,
            String requestId,
            int status,
            String code,
            boolean retryable
    ) throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json");
        response.setHeader("X-Request-Id", requestId);
        objectMapper.writeValue(
                response.getOutputStream(),
                new ApiErrorResponse(
                        code,
                        messageFor(code),
                        requestId,
                        retryable
                )
        );
    }

    private String messageFor(String code) {
        return switch (code) {
            case "UPSTREAM_ERROR" -> "Upstream request failed";
            case "UPSTREAM_TIMEOUT" -> "Upstream request timed out";
            case "TARGET_STORE_UNAVAILABLE" ->
                    "Upstream target service is unavailable";
            case "REQUEST_READ_FAILED" -> "Request body could not be read";
            case "REQUEST_TOO_LARGE" -> "Request body is too large";
            case "INTERNAL_CONFIGURATION" ->
                    "Authentication configuration is invalid";
            default -> "Internal server error";
        };
    }

    private boolean isPublicApiPath(String requestUri) {
        return "/open/v1".equals(requestUri)
                || (requestUri != null && requestUri.startsWith("/open/v1/"));
    }

    private static final class RequestTooLargeException
            extends RuntimeException {
    }

    @Override
    public void destroy() {
        // No resources to release.
    }
}
