package com.apiproject.app;

import com.apiproject.app.security.CredentialSecretDecryptor;
import com.apiproject.gateway.security.HmacCanonicalRequest;
import com.apiproject.gateway.security.HmacCanonicalizer;
import com.apiproject.gateway.security.HmacAuthenticationFilter;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.flywaydb.core.Flyway;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import redis.embedded.RedisServer;

import javax.sql.DataSource;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = {
                ApiOpenPlatformApplication.class,
                RuntimeHmacIntegrationTest.TestBeans.class
        }
)
class RuntimeHmacIntegrationTest {

    private static final Instant NOW = Instant.ofEpochSecond(1_760_000_000L);
    private static final byte[] SECRET = bytes(
            "runtime-secret-0123456789abcdef0123456789abcdef"
    );
    private static final UUID PROBE_API_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID PROBE_VERSION_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000002");
    private static final UUID PROBE_PUBLICATION_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000003");
    private static final UUID PROBE_OWNER_TENANT_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000004");
    private static final UUID PROBE_OWNER_USER_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000005");
    private static final EmbeddedPostgres POSTGRES = startPostgres();
    private static final DataSource ADMIN_DATA_SOURCE = POSTGRES.getPostgresDatabase();
    private static final JdbcTemplate ADMIN_JDBC = new JdbcTemplate(ADMIN_DATA_SOURCE);
    private static final boolean ADMIN_SCHEMA_READY = prepareRestrictedRole();
    private static final int REDIS_PORT = freePort();
    private static final RedisServer REDIS = startRedis(REDIS_PORT);

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final HmacCanonicalizer canonicalizer = HmacCanonicalizer.createDefault();

    @LocalServerPort
    private int serverPort;

    @DynamicPropertySource
    static void runtimeProperties(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> POSTGRES.getJdbcUrl("gateway_staging", "postgres")
        );
        registry.add("spring.datasource.username", () -> "gateway_staging");
        registry.add("spring.datasource.password", () -> "test-password");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add(
                "gateway.security.redis-uri",
                () -> "redis://127.0.0.1:" + REDIS_PORT
        );
        registry.add("gateway.security.kms.enabled", () -> "false");
    }

    @AfterAll
    static void stopServices() throws Exception {
        REDIS.stop();
        POSTGRES.close();
    }

    @Test
    void signedRequestPassesThroughRegisteredFilterAndReplayIsRejected()
            throws Exception {
        String appKey = insertCredential("ACTIVE", "ACTIVE");
        grantProbeApi(appKey);
        String nonce = "nonce-" + UUID.randomUUID();
        String host = "127.0.0.1:" + serverPort;
        long timestamp = NOW.getEpochSecond();
        String signature = signature(
                appKey,
                host,
                timestamp,
                nonce
        );
        HttpRequest request = request(
                appKey,
                timestamp,
                nonce,
                signature
        );

        HttpResponse<String> success = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );
        HttpResponse<String> replay = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(200, success.statusCode(), success.body());
        assertTrue(success.body().contains(appKey));
        assertTrue(success.headers().firstValue("X-Request-Id").isPresent());
        assertEquals(401, replay.statusCode());
        assertTrue(replay.body().contains("NONCE_REPLAYED"));
    }

    @Test
    void suspendedAppFailsClosedBeforeController() throws Exception {
        String appKey = insertCredential("SUSPENDED", "ACTIVE");
        String nonce = "nonce-" + UUID.randomUUID();
        long timestamp = NOW.getEpochSecond();
        String host = "127.0.0.1:" + serverPort;

        HttpResponse<String> response = httpClient.send(
                request(
                        appKey,
                        timestamp,
                        nonce,
                        signature(appKey, host, timestamp, nonce)
                ),
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(401, response.statusCode());
        assertTrue(response.body().contains("INVALID_CREDENTIAL"));
    }

    @Test
    void activeAppWithoutGrantReturns403() throws Exception {
        String appKey = insertCredential("ACTIVE", "ACTIVE");
        ensureProbeApi();
        String nonce = "nonce-" + UUID.randomUUID();
        long timestamp = NOW.getEpochSecond();
        String host = "127.0.0.1:" + serverPort;

        HttpResponse<String> response = httpClient.send(
                request(
                        appKey,
                        timestamp,
                        nonce,
                        signature(appKey, host, timestamp, nonce)
                ),
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(403, response.statusCode());
        assertTrue(response.body().contains("API_NOT_GRANTED"));
    }

    private HttpRequest request(
            String appKey,
            long timestamp,
            String nonce,
            String signature
    ) {
        return HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + serverPort + "/open/v1/probe"))
                .GET()
                .header("X-Signature-Version", "v1")
                .header("X-App-Key", appKey)
                .header("X-Timestamp", Long.toString(timestamp))
                .header("X-Nonce", nonce)
                .header("X-Signature", signature)
                .build();
    }

    private String signature(
            String appKey,
            String host,
            long timestamp,
            String nonce
    ) {
        return canonicalizer.canonicalize(
                new HmacCanonicalRequest(
                        appKey,
                        "GET",
                        host,
                        "/open/v1/probe",
                        null,
                        null,
                        timestamp,
                        nonce,
                        bytes("")
                ),
                SECRET
        ).signatureHex();
    }

    private String insertCredential(String appStatus, String credentialStatus) {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        UUID appId = UUID.randomUUID();
        String suffix = tenantId.toString().substring(0, 8);
        String appKey = "ak_runtime_" + suffix + "_1234567890";
        String tenantCode = "runtime-" + suffix;

        ADMIN_JDBC.update(
                """
                INSERT INTO iam_tenant (id, code, name, status, auth_epoch)
                VALUES (?, ?, ?, 'ACTIVE', 1)
                """,
                tenantId,
                tenantCode,
                tenantCode
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO iam_user (id, email, password_hash, mfa_enabled, status)
                VALUES (?, ?, 'argon2-test-hash', false, 'ACTIVE')
                """,
                userId,
                "runtime-" + suffix + "@example.com"
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO iam_role_binding (
                    tenant_id, user_id, role_code, scope_type
                ) VALUES (?, ?, 'APP_DEVELOPER', 'TENANT')
                """,
                tenantId,
                userId
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO app (
                    id, tenant_id, name, owner_user_id, status, auth_epoch
                ) VALUES (?, ?, ?, ?, ?, 1)
                """,
                appId,
                tenantId,
                "runtime-app-" + suffix,
                userId,
                appStatus
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO app_credential (
                    id, tenant_id, app_id, app_key, secret_ciphertext, kms_key_id,
                    status, auth_epoch
                ) VALUES (?, ?, ?, ?, ?, 'test-kms-key', ?, 1)
                """,
                UUID.randomUUID(),
                tenantId,
                appId,
                appKey,
                new byte[]{9, 8, 7},
                credentialStatus
        );
        return appKey;
    }

    private static EmbeddedPostgres startPostgres() {
        try {
            return EmbeddedPostgres.builder().start();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private static boolean prepareRestrictedRole() {
        Flyway.configure()
                .dataSource(ADMIN_DATA_SOURCE)
                .locations("classpath:db/migration")
                .load()
                .migrate();
        ADMIN_JDBC.execute("DROP ROLE IF EXISTS gateway_staging");
        ADMIN_JDBC.execute("""
                CREATE ROLE gateway_staging
                LOGIN PASSWORD 'test-password'
                NOSUPERUSER NOBYPASSRLS
                """);
        ADMIN_JDBC.execute(
                "GRANT CONNECT ON DATABASE postgres TO gateway_staging"
        );
        ADMIN_JDBC.execute("GRANT USAGE ON SCHEMA public TO gateway_staging");
        ADMIN_JDBC.execute("""
                GRANT EXECUTE
                ON FUNCTION auth_resolve_active_credential(text)
                TO gateway_staging
                """);
        ADMIN_JDBC.execute("""
                GRANT EXECUTE
                ON FUNCTION auth_authorize_public_api(text,text,text)
                TO gateway_staging
                """);
        return true;
    }

    private void grantProbeApi(String appKey) {
        ensureProbeApi();
        ADMIN_JDBC.update(
                """
                INSERT INTO app_api_grant (
                    tenant_id, app_id, api_id, granted_by, status, auth_epoch
                )
                SELECT tenant_id, app_id, ?, ?, 'ACTIVE', 1
                FROM app_credential
                WHERE app_key = ?
                """,
                PROBE_API_ID,
                PROBE_OWNER_USER_ID,
                appKey
        );
    }

    private void ensureProbeApi() {
        Integer count = ADMIN_JDBC.queryForObject(
                "SELECT count(*) FROM api_definition WHERE id = ?",
                Integer.class,
                PROBE_API_ID
        );
        if (count != null && count > 0) {
            return;
        }

        ADMIN_JDBC.update(
                """
                INSERT INTO iam_tenant (id, code, name, status, auth_epoch)
                VALUES (?, 'probe-owner', 'Probe Owner', 'ACTIVE', 1)
                """,
                PROBE_OWNER_TENANT_ID
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO iam_user (
                    id, email, password_hash, mfa_enabled, status
                ) VALUES (
                    ?, 'probe-owner@example.com', 'argon2-test-hash', false, 'ACTIVE'
                )
                """,
                PROBE_OWNER_USER_ID
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO api_definition (
                    id, owner_tenant_id, code, name, public_method, public_path,
                    kind, visibility, status, publish_epoch
                ) VALUES (
                    ?, ?, 'runtime-probe', 'Runtime Probe', 'GET', '/open/v1/probe',
                    'PROXY', 'PLATFORM_PUBLIC', 'PUBLISHED', 1
                )
                """,
                PROBE_API_ID,
                PROBE_OWNER_TENANT_ID
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO api_version (
                    id, api_id, version, status, request_schema, response_schema,
                    timeout_ms, config_json, config_checksum, created_by
                ) VALUES (
                    ?, ?, 1, 'PUBLISHED', '{"type":"object"}'::jsonb,
                    '{"type":"object"}'::jsonb, 1000,
                    '{"upstreamEndpointId":"00000000-0000-0000-0000-000000000001"}'::jsonb,
                    repeat('a', 64), ?
                )
                """,
                PROBE_VERSION_ID,
                PROBE_API_ID,
                PROBE_OWNER_USER_ID
        );
        ADMIN_JDBC.update(
                """
                INSERT INTO api_publication (
                    id, api_id, owner_tenant_id, visibility, api_version_id,
                    environment, publication_no, status, manifest_json,
                    manifest_checksum, published_by
                ) VALUES (
                    ?, ?, ?, 'PLATFORM_PUBLIC', ?, 'PROD', 1, 'ACTIVE',
                    '{"requiredApis":[]}'::jsonb, repeat('b', 64), ?
                )
                """,
                PROBE_PUBLICATION_ID,
                PROBE_API_ID,
                PROBE_OWNER_TENANT_ID,
                PROBE_VERSION_ID,
                PROBE_OWNER_USER_ID
        );
        ADMIN_JDBC.update(
                """
                UPDATE api_definition
                SET active_prod_publication_id = ?, publish_epoch = publish_epoch + 1
                WHERE id = ?
                """,
                PROBE_PUBLICATION_ID,
                PROBE_API_ID
        );
    }

    private static RedisServer startRedis(int port) {
        try {
            RedisServer server = RedisServer.newRedisServer()
                    .port(port)
                    .setting("bind 127.0.0.1")
                    .setting("save \"\"")
                    .setting("appendonly no")
                    .build();
            server.start();
            return server;
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestBeans {

        @Bean
        @Primary
        Clock clock() {
            return Clock.fixed(NOW, ZoneOffset.UTC);
        }

        @Bean
        CredentialSecretDecryptor credentialSecretDecryptor() {
            return (context, ciphertext) -> SECRET.clone();
        }

        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {

        @GetMapping("/open/v1/probe")
        ProbeResponse probe(HttpServletRequest request) {
            return new ProbeResponse(
                    (String) request.getAttribute(
                            HmacAuthenticationFilter.AUTHENTICATED_APP_KEY_ATTRIBUTE
                    ),
                    (String) request.getAttribute(
                            HmacAuthenticationFilter.REQUEST_ID_ATTRIBUTE
                    )
            );
        }
    }

    record ProbeResponse(String appKey, String requestId) {
    }
}
