package com.apiproject.gateway.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class JdkUpstreamClient implements UpstreamClient {

    public static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final int ABSOLUTE_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    private final HttpClient httpClient;
    private final int maxResponseBytes;

    public JdkUpstreamClient() {
        this(
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    public JdkUpstreamClient(int maxResponseBytes) {
        this(
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                maxResponseBytes
        );
    }

    public JdkUpstreamClient(
            HttpClient httpClient,
            int maxResponseBytes
    ) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        if (maxResponseBytes < 1
                || maxResponseBytes > ABSOLUTE_MAX_RESPONSE_BYTES) {
            throw new IllegalArgumentException(
                    "maxResponseBytes is outside the allowed range"
            );
        }
        this.maxResponseBytes = maxResponseBytes;
    }

    @Override
    public UpstreamResponse execute(UpstreamRequest request) {
        Objects.requireNonNull(request, "request");
        HttpRequest httpRequest = buildRequest(request);
        try {
            HttpResponse<InputStream> response = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofInputStream()
            );
            try (InputStream input = response.body()) {
                long declaredLength = response.headers()
                        .firstValueAsLong("Content-Length")
                        .orElse(-1);
                if (declaredLength > maxResponseBytes) {
                    throw responseTooLarge();
                }
                byte[] body = input.readNBytes(maxResponseBytes + 1);
                if (body.length > maxResponseBytes) {
                    throw responseTooLarge();
                }
                return new UpstreamResponse(
                        response.statusCode(),
                        response.headers().map(),
                        body
                );
            }
        } catch (HttpTimeoutException exception) {
            throw new UpstreamClientException(
                    UpstreamClientException.Code.TIMEOUT,
                    "Upstream request timed out",
                    exception
            );
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new UpstreamClientException(
                    UpstreamClientException.Code.TRANSPORT,
                    "Upstream request was interrupted",
                    exception
            );
        } catch (IOException exception) {
            throw new UpstreamClientException(
                    UpstreamClientException.Code.TRANSPORT,
                    "Upstream transport failed",
                    exception
            );
        }
    }

    private HttpRequest buildRequest(UpstreamRequest request) {
        HttpRequest.BodyPublisher publisher = request.body().length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(request.body());
        HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri())
                .timeout(request.timeout())
                .method(request.method(), publisher);
        request.headers().forEach((name, values) ->
                values.forEach(value ->
                        builder.header(name, value)
                )
        );
        return builder.build();
    }

    private UpstreamClientException responseTooLarge() {
        return new UpstreamClientException(
                UpstreamClientException.Code.RESPONSE_TOO_LARGE,
                "Upstream response exceeded the configured limit",
                null
        );
    }
}
