package com.apiproject.gateway.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JdkUpstreamClientTest {

    private HttpServer server;
    private ExecutorService executor;
    private URI baseUri;
    private JdkUpstreamClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        executor = Executors.newCachedThreadPool();
        server.setExecutor(executor);
        server.createContext("/echo", exchange -> respondEcho(exchange));
        server.createContext("/large", exchange -> {
            byte[] body = "x".repeat(1024).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/slow", exchange -> {
            try {
                Thread.sleep(300);
                exchange.sendResponseHeaders(200, 0);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();
        baseUri = URI.create(
                "http://127.0.0.1:" + server.getAddress().getPort()
        );
        client = new JdkUpstreamClient(256);
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Test
    void sendsMethodHeadersBodyAndReadsBoundedResponse() {
        UpstreamResponse response = client.execute(new UpstreamRequest(
                baseUri.resolve("/echo?mode=test"),
                "POST",
                Map.of(
                        "Content-Type", List.of("text/plain"),
                        "X-Test", List.of("one", "two")
                ),
                "hello".getBytes(StandardCharsets.UTF_8),
                Duration.ofSeconds(2)
        ));

        assertEquals(201, response.status());
        assertEquals(
                "hello|POST|/echo?mode=test|one,two|text/plain",
                new String(response.body(), StandardCharsets.UTF_8)
        );
        assertEquals(
                "application/json",
                response.headers().get("content-type").get(0)
        );
    }

    @Test
    void oversizedResponseFailsClosed() {
        UpstreamClientException exception = assertThrows(
                UpstreamClientException.class,
                () -> client.execute(new UpstreamRequest(
                        baseUri.resolve("/large"),
                        "GET",
                        Map.of(),
                        new byte[0],
                        Duration.ofSeconds(2)
                ))
        );

        assertEquals(
                UpstreamClientException.Code.RESPONSE_TOO_LARGE,
                exception.code()
        );
    }

    @Test
    void timeoutIsReportedAsTimeout() {
        UpstreamClientException exception = assertThrows(
                UpstreamClientException.class,
                () -> client.execute(new UpstreamRequest(
                        baseUri.resolve("/slow"),
                        "GET",
                        Map.of(),
                        new byte[0],
                        Duration.ofMillis(50)
                ))
        );

        assertEquals(UpstreamClientException.Code.TIMEOUT, exception.code());
    }

    private void respondEcho(HttpExchange exchange) throws IOException {
        byte[] requestBody = exchange.getRequestBody().readAllBytes();
        String body = new String(requestBody, StandardCharsets.UTF_8)
                + "|" + exchange.getRequestMethod()
                + "|" + exchange.getRequestURI()
                + "|" + String.join(
                        ",",
                        exchange.getRequestHeaders().get("X-Test")
                )
                + "|" + exchange.getRequestHeaders()
                        .getFirst("Content-Type");
        byte[] response = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("X-Internal", "hidden");
        exchange.sendResponseHeaders(201, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }
}
