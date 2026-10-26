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
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public final class HmacAuthenticationFilter implements Filter {

    public static final int MAX_BODY_BYTES = 1024 * 1024;
    public static final String AUTHENTICATED_APP_KEY_ATTRIBUTE =
            HmacAuthenticationFilter.class.getName() + ".appKey";
    public static final String REQUEST_ID_ATTRIBUTE =
            HmacAuthenticationFilter.class.getName() + ".requestId";
    public static final String AUTHORIZED_API_ATTRIBUTE =
            HmacAuthenticationFilter.class.getName() + ".authorizedApi";

    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("^[0-9]{10}$");
    private static final List<String> AUTH_HEADERS = List.of(
            "X-Signature-Version",
            "X-App-Key",
            "X-Timestamp",
            "X-Nonce",
            "X-Signature"
    );
    private static final List<String> UNIQUE_HEADERS = List.of(
            "Host",
            "Content-Length",
            "Content-Type",
            "X-Signature-Version",
            "X-App-Key",
            "X-Timestamp",
            "X-Nonce",
            "X-Signature"
    );

    private final ActiveCredentialResolver credentialResolver;
    private final HmacRequestAuthenticator authenticator;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final ApiAuthorizationGate authorizationGate;

    public HmacAuthenticationFilter(
            ActiveCredentialResolver credentialResolver,
            HmacRequestAuthenticator authenticator,
            ObjectMapper objectMapper,
            Clock clock,
            ApiAuthorizationGate authorizationGate
    ) {
        this.credentialResolver = Objects.requireNonNull(
                credentialResolver,
                "credentialResolver"
        );
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.authorizationGate = Objects.requireNonNull(
                authorizationGate,
                "authorizationGate"
        );
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

        String requestId = UUID.randomUUID().toString();
        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
        response.setHeader("X-Request-Id", requestId);

        HttpServletRequest authenticatedRequest;
        try {
            authenticatedRequest = authenticate(request, requestId);
            String appKey = (String) authenticatedRequest.getAttribute(
                    AUTHENTICATED_APP_KEY_ATTRIBUTE
            );
            AuthorizedApi authorizedApi = authorizationGate.authorize(
                    appKey,
                    request.getMethod(),
                    request.getRequestURI()
            );
            authenticatedRequest.setAttribute(
                    AUTHORIZED_API_ATTRIBUTE,
                    authorizedApi
            );
        } catch (FilterException exception) {
            writeError(
                    response,
                    requestId,
                    exception.status,
                    exception.code,
                    exception.retryable
            );
            return;
        } catch (ApiAuthorizationException exception) {
            ErrorMapping mapping = mapAuthorizationError(exception.code());
            writeError(
                    response,
                    requestId,
                    mapping.status,
                    exception.code(),
                    mapping.retryable
            );
            return;
        } catch (HmacVerificationException exception) {
            ErrorMapping mapping = mapVerificationError(exception.code());
            writeError(
                    response,
                    requestId,
                    mapping.status,
                    exception.code(),
                    mapping.retryable
            );
            return;
        } catch (IOException exception) {
            writeError(
                    response,
                    requestId,
                    400,
                    "REQUEST_READ_FAILED",
                    false
            );
            return;
        } catch (RuntimeException exception) {
            writeError(
                    response,
                    requestId,
                    500,
                    "INTERNAL_ERROR",
                    false
            );
            return;
        }

        chain.doFilter(authenticatedRequest, response);
    }

    private HttpServletRequest authenticate(
            HttpServletRequest request,
            String requestId
    ) throws IOException {
        checkDuplicateHeaders(request);

        String version = requiredHeader(
                request,
                "X-Signature-Version",
                400,
                "UNSUPPORTED_SIGNATURE_VERSION"
        );
        if (!"v1".equals(version)) {
            throw new FilterException(
                    400,
                    "UNSUPPORTED_SIGNATURE_VERSION",
                    false
            );
        }

        String appKey = requiredHeader(
                request,
                "X-App-Key",
                401,
                "MISSING_AUTH_HEADER"
        );
        String timestampHeader = requiredHeader(
                request,
                "X-Timestamp",
                401,
                "MISSING_AUTH_HEADER"
        );
        String nonce = requiredHeader(
                request,
                "X-Nonce",
                401,
                "MISSING_AUTH_HEADER"
        );
        String signature = requiredHeader(
                request,
                "X-Signature",
                401,
                "MISSING_AUTH_HEADER"
        );
        String host = requiredHeader(
                request,
                "Host",
                400,
                "MISSING_HOST"
        );

        if (!TIMESTAMP_PATTERN.matcher(timestampHeader).matches()) {
            throw new FilterException(400, "INVALID_TIMESTAMP_FORMAT", false);
        }
        long timestamp;
        try {
            timestamp = Long.parseLong(timestampHeader);
        } catch (NumberFormatException exception) {
            throw new FilterException(400, "INVALID_TIMESTAMP_FORMAT", false);
        }

        byte[] body = readBody(request);
        CachedBodyHttpServletRequest cachedRequest =
                new CachedBodyHttpServletRequest(request, body);

        Optional<byte[]> resolvedSecret;
        try {
            resolvedSecret = credentialResolver.resolveActiveSecret(appKey);
        } catch (CredentialResolutionException exception) {
            throw new FilterException(
                    exception.retryable() ? 503 : 500,
                    exception.code(),
                    exception.retryable()
            );
        } catch (RuntimeException exception) {
            throw new FilterException(
                    503,
                    "CREDENTIAL_STORE_UNAVAILABLE",
                    true
            );
        }
        if (resolvedSecret == null || resolvedSecret.isEmpty()) {
            throw new FilterException(401, "INVALID_CREDENTIAL", false);
        }

        byte[] secret = resolvedSecret.get();
        try {
            HmacCanonicalRequest canonicalRequest = new HmacCanonicalRequest(
                    appKey,
                    request.getMethod(),
                    host,
                    request.getRequestURI(),
                    request.getQueryString(),
                    request.getContentType(),
                    timestamp,
                    nonce,
                    body
            );
            authenticator.authenticate(
                    canonicalRequest,
                    signature,
                    secret,
                    clock.instant()
            );
        } finally {
            Arrays.fill(secret, (byte) 0);
        }

        cachedRequest.setAttribute(AUTHENTICATED_APP_KEY_ATTRIBUTE, appKey);
        cachedRequest.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
        return cachedRequest;
    }

    private byte[] readBody(HttpServletRequest request) throws IOException {
        long declaredLength = declaredContentLength(request);
        if (declaredLength > MAX_BODY_BYTES) {
            throw new FilterException(413, "REQUEST_TOO_LARGE", false);
        }
        byte[] body = request.getInputStream().readNBytes(MAX_BODY_BYTES + 1);
        if (body.length > MAX_BODY_BYTES) {
            throw new FilterException(413, "REQUEST_TOO_LARGE", false);
        }
        return body;
    }

    private long declaredContentLength(HttpServletRequest request) {
        String header = request.getHeader("Content-Length");
        if (header == null || header.isBlank()) {
            return request.getContentLengthLong();
        }
        try {
            long value = Long.parseLong(header);
            if (value < 0) {
                throw new NumberFormatException("negative");
            }
            return value;
        } catch (NumberFormatException exception) {
            throw new FilterException(400, "INVALID_CONTENT_LENGTH", false);
        }
    }

    private void checkDuplicateHeaders(HttpServletRequest request) {
        for (String name : UNIQUE_HEADERS) {
            List<String> values = Collections.list(request.getHeaders(name));
            if (values.size() > 1) {
                throw new FilterException(400, "DUPLICATE_HEADER", false);
            }
        }
    }

    private String requiredHeader(
            HttpServletRequest request,
            String name,
            int status,
            String code
    ) {
        List<String> values = Collections.list(request.getHeaders(name));
        if (values.isEmpty() || values.get(0) == null || values.get(0).isBlank()) {
            throw new FilterException(status, code, false);
        }
        return values.get(0);
    }

    private boolean isPublicApiPath(String requestUri) {
        return "/open/v1".equals(requestUri)
                || (requestUri != null && requestUri.startsWith("/open/v1/"));
    }

    private ErrorMapping mapVerificationError(String code) {
        return switch (code) {
            case "INVALID_REQUEST" -> new ErrorMapping(400, false);
            case "INVALID_SIGNATURE_FORMAT",
                 "TIMESTAMP_OUT_OF_WINDOW",
                 "INVALID_SIGNATURE",
                 "NONCE_REPLAYED",
                 "INVALID_CREDENTIAL" -> new ErrorMapping(401, false);
            case "NONCE_STORE_UNAVAILABLE",
                 "CREDENTIAL_STORE_UNAVAILABLE" -> new ErrorMapping(503, true);
            case "INTERNAL_CONFIGURATION" -> new ErrorMapping(500, false);
            default -> new ErrorMapping(500, false);
        };
    }

    private ErrorMapping mapAuthorizationError(String code) {
        return switch (code) {
            case "INVALID_CREDENTIAL" -> new ErrorMapping(401, false);
            case "API_NOT_GRANTED" -> new ErrorMapping(403, false);
            case "API_NOT_FOUND" -> new ErrorMapping(404, false);
            case "AUTHORIZATION_STORE_UNAVAILABLE" -> new ErrorMapping(503, true);
            default -> new ErrorMapping(500, false);
        };
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
            case "REQUEST_TOO_LARGE" -> "Request body is too large";
            case "INVALID_CONTENT_LENGTH" -> "Content-Length is invalid";
            case "MISSING_AUTH_HEADER" -> "Authentication headers are incomplete";
            case "DUPLICATE_HEADER" -> "Duplicate or ambiguous headers are not allowed";
            case "UNSUPPORTED_SIGNATURE_VERSION" -> "Signature version is not supported";
            case "INVALID_TIMESTAMP_FORMAT" -> "Timestamp format is invalid";
            case "TIMESTAMP_OUT_OF_WINDOW" -> "Request timestamp is outside the allowed window";
            case "INVALID_SIGNATURE_FORMAT" -> "Signature format is invalid";
            case "INVALID_SIGNATURE" -> "Signature verification failed";
            case "NONCE_REPLAYED" -> "Request has already been used";
            case "INVALID_CREDENTIAL" -> "Credential is invalid";
            case "NONCE_STORE_UNAVAILABLE" -> "Authentication service is unavailable";
            case "CREDENTIAL_STORE_UNAVAILABLE" -> "Credential service is unavailable";
            case "INVALID_REQUEST" -> "Request is invalid";
            case "INTERNAL_CONFIGURATION" -> "Authentication configuration is invalid";
            case "REQUEST_READ_FAILED" -> "Request body could not be read";
            case "API_NOT_FOUND" -> "API was not found";
            case "API_NOT_GRANTED" -> "Application is not granted this API";
            case "AUTHORIZATION_STORE_UNAVAILABLE" ->
                    "Authorization service is unavailable";
            default -> "Authentication failed";
        };
    }

    @Override
    public void destroy() {
        // No resources to release.
    }

    private static final class FilterException extends RuntimeException {
        private final int status;
        private final String code;
        private final boolean retryable;

        private FilterException(int status, String code, boolean retryable) {
            this.status = status;
            this.code = code;
            this.retryable = retryable;
        }
    }

    private record ErrorMapping(int status, boolean retryable) {
    }
}
