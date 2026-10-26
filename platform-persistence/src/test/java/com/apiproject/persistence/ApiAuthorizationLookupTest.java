package com.apiproject.persistence;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiAuthorizationLookupTest {

    private static final String FUNCTION_CALL = """
            SELECT decision, app_id, api_id, api_version_id, visibility
            FROM auth_authorize_public_api(?, ?, ?)
            """;
    private static final String POLICY_FUNCTION_CALL = """
            SELECT
                app_rate_requests,
                app_rate_window_seconds,
                app_rate_burst,
                api_rate_requests,
                api_rate_window_seconds,
                api_rate_burst,
                app_daily_quota,
                app_monthly_quota,
                api_daily_quota,
                api_monthly_quota
            FROM auth_resolve_post_auth_policies(?, ?)
            """;

    private static EmbeddedPostgres postgres;
    private static DataSource dataSource;

    @BeforeAll
    static void migrateDatabase() throws Exception {
        postgres = EmbeddedPostgres.builder().start();
        dataSource = postgres.getPostgresDatabase();
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();
        createRuntimeRole();
    }

    @AfterAll
    static void closeDatabase() throws Exception {
        if (postgres != null) {
            postgres.close();
        }
    }

    @Test
    void allowsActiveGrantForPublishedApi() throws Exception {
        Fixture fixture = insertFixture("PLATFORM_PUBLIC", true, "ACTIVE");

        Decision decision = authorize(
                fixture.appKey(),
                "GET",
                fixture.path()
        );

        assertEquals("ALLOWED", decision.code());
        assertEquals(fixture.appId(), decision.appId());
        assertEquals(fixture.apiId(), decision.apiId());
        assertEquals(fixture.apiVersionId(), decision.apiVersionId());
        assertEquals("PLATFORM_PUBLIC", decision.visibility());
    }

    @Test
    void resolvesApplicationAndApiPolicyOverrides() throws Exception {
        Fixture fixture = insertFixture("PLATFORM_PUBLIC", true, "ACTIVE");
        insertRateLimitPolicy(
                fixture.tenantId(),
                "APP",
                fixture.appId(),
                30,
                60,
                6
        );
        insertRateLimitPolicy(
                null,
                "API",
                fixture.apiId(),
                20,
                60,
                4
        );
        insertQuotaPolicy(
                fixture.tenantId(),
                "APP",
                fixture.appId(),
                "DAY",
                1_000
        );
        insertQuotaPolicy(
                fixture.tenantId(),
                "APP",
                fixture.appId(),
                "MONTH",
                10_000
        );
        insertQuotaPolicy(
                null,
                "API",
                fixture.apiId(),
                "DAY",
                500
        );
        insertQuotaPolicy(
                null,
                "API",
                fixture.apiId(),
                "MONTH",
                5_000
        );

        EffectivePolicy policy = resolvePolicies(
                fixture.appId(),
                fixture.apiId()
        );

        assertEquals(30L, policy.appRateRequests());
        assertEquals(60, policy.appRateWindowSeconds());
        assertEquals(6, policy.appRateBurst());
        assertEquals(20L, policy.apiRateRequests());
        assertEquals(60, policy.apiRateWindowSeconds());
        assertEquals(4, policy.apiRateBurst());
        assertEquals(1_000L, policy.appDailyQuota());
        assertEquals(10_000L, policy.appMonthlyQuota());
        assertEquals(500L, policy.apiDailyQuota());
        assertEquals(5_000L, policy.apiMonthlyQuota());
    }

    @Test
    void returnsNullPolicyFieldsWhenNoOverridesExist() throws Exception {
        Fixture fixture = insertFixture("PLATFORM_PUBLIC", true, "ACTIVE");

        EffectivePolicy policy = resolvePolicies(
                fixture.appId(),
                fixture.apiId()
        );

        assertNull(policy.appRateRequests());
        assertNull(policy.appRateWindowSeconds());
        assertNull(policy.appRateBurst());
        assertNull(policy.appDailyQuota());
        assertNull(policy.apiMonthlyQuota());
    }

    @Test
    void missingOrRevokedGrantReturnsApiNotGranted() throws Exception {
        Fixture missing = insertFixture("PLATFORM_PUBLIC", false, "ACTIVE");
        Fixture revoked = insertFixture("PLATFORM_PUBLIC", true, "REVOKED");

        assertEquals(
                "API_NOT_GRANTED",
                authorize(missing.appKey(), "GET", missing.path()).code()
        );
        assertEquals(
                "API_NOT_GRANTED",
                authorize(revoked.appKey(), "GET", revoked.path()).code()
        );
    }

    @Test
    void unknownMethodOrPathReturnsApiNotFound() throws Exception {
        Fixture fixture = insertFixture("PLATFORM_PUBLIC", true, "ACTIVE");

        assertEquals(
                "API_NOT_FOUND",
                authorize(fixture.appKey(), "POST", fixture.path()).code()
        );
        assertEquals(
                "API_NOT_FOUND",
                authorize(
                        fixture.appKey(),
                        "GET",
                        fixture.path() + "-unknown"
                ).code()
        );
    }

    @Test
    void privateApiVisibilityAndCredentialRaceFailClosed() throws Exception {
        Fixture foreignPrivate = insertForeignPrivateFixture();
        Fixture invalidCredential = insertFixture(
                "PLATFORM_PUBLIC",
                true,
                "ACTIVE"
        );
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE app_credential
                     SET status = 'REVOKED'
                     WHERE app_key = ?
                     """)) {
            statement.setString(1, invalidCredential.appKey());
            statement.executeUpdate();
        }

        assertEquals(
                "API_NOT_FOUND",
                authorize(
                        foreignPrivate.appKey(),
                        "GET",
                        foreignPrivate.path()
                ).code()
        );
        assertEquals(
                "INVALID_CREDENTIAL",
                authorize(
                        invalidCredential.appKey(),
                        "GET",
                        invalidCredential.path()
                ).code()
        );
    }

    private static Decision authorize(
            String appKey,
            String method,
            String path
    ) throws SQLException {
        try (Connection connection = runtimeConnection();
             PreparedStatement statement = connection.prepareStatement(FUNCTION_CALL)) {
            statement.setString(1, appKey);
            statement.setString(2, method);
            statement.setString(3, path);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                Decision decision = new Decision(
                        resultSet.getString(1),
                        resultSet.getObject(2, UUID.class),
                        resultSet.getObject(3, UUID.class),
                        resultSet.getObject(4, UUID.class),
                        resultSet.getString(5)
                );
                assertFalse(resultSet.next());
                return decision;
            }
        }
    }

    private static Fixture insertFixture(
            String visibility,
            boolean grant,
            String grantStatus
    ) throws SQLException {
        FixtureIdentity owner = insertOwner();
        return insertApiForOwner(owner, visibility, grant, grantStatus);
    }

    private static Fixture insertForeignPrivateFixture() throws SQLException {
        FixtureIdentity caller = insertOwner();
        FixtureIdentity foreignOwner = insertOwner();
        Fixture foreignApi = insertApiForOwner(
                foreignOwner,
                "TENANT_PRIVATE",
                false,
                "ACTIVE"
        );
        insertGrant(
                caller,
                foreignApi.apiId(),
                "ACTIVE"
        );
        return new Fixture(
                caller.appKey(),
                caller.tenantId(),
                caller.appId(),
                foreignApi.apiId(),
                foreignApi.apiVersionId(),
                foreignApi.path()
        );
    }

    private static FixtureIdentity insertOwner() throws SQLException {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        UUID appId = UUID.randomUUID();
        String suffix = tenantId.toString().substring(0, 8);
        String appKey = "ak_authorization_" + suffix + "_123456";
        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenantId, suffix);
            insertUserAndRole(connection, tenantId, userId, suffix);
            insertApp(connection, tenantId, userId, appId, suffix);
            insertCredential(connection, tenantId, appId, appKey);
        }
        return new FixtureIdentity(tenantId, userId, appId, appKey);
    }

    private static Fixture insertApiForOwner(
            FixtureIdentity owner,
            String visibility,
            boolean grant,
            String grantStatus
    ) throws SQLException {
        UUID apiId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        UUID publicationId = UUID.randomUUID();
        try (Connection connection = dataSource.getConnection()) {
            insertApiDefinition(
                    connection,
                    owner.tenantId(),
                    owner.userId(),
                    apiId,
                    visibility,
                    "TENANT_PRIVATE".equals(visibility)
                            ? "/open/v1/private/" + apiId
                            : "/open/v1/orders/" + apiId
            );
            insertApiVersion(connection, apiId, owner.userId(), versionId);
            insertPublication(
                    connection,
                    publicationId,
                    apiId,
                    owner.tenantId(),
                    versionId,
                    owner.userId()
            );
            activate(connection, apiId, publicationId);
            if (grant) {
                insertGrant(connection, owner, apiId, grantStatus);
            }
        }
        return new Fixture(
                owner.appKey(),
                owner.tenantId(),
                owner.appId(),
                apiId,
                versionId,
                "TENANT_PRIVATE".equals(visibility)
                        ? "/open/v1/private/" + apiId
                        : "/open/v1/orders/" + apiId
        );
    }

    private static void insertGrant(
            FixtureIdentity caller,
            UUID apiId,
            String status
    ) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            insertGrant(connection, caller, apiId, status);
        }
    }

    private static EffectivePolicy resolvePolicies(
            UUID appId,
            UUID apiId
    ) throws SQLException {
        try (Connection connection = runtimeConnection();
             PreparedStatement statement = connection.prepareStatement(
                     POLICY_FUNCTION_CALL
             )) {
            statement.setObject(1, appId);
            statement.setObject(2, apiId);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                EffectivePolicy policy = new EffectivePolicy(
                        resultSet.getObject("app_rate_requests", Long.class),
                        resultSet.getObject(
                                "app_rate_window_seconds",
                                Integer.class
                        ),
                        resultSet.getObject("app_rate_burst", Integer.class),
                        resultSet.getObject("api_rate_requests", Long.class),
                        resultSet.getObject(
                                "api_rate_window_seconds",
                                Integer.class
                        ),
                        resultSet.getObject("api_rate_burst", Integer.class),
                        resultSet.getObject("app_daily_quota", Long.class),
                        resultSet.getObject("app_monthly_quota", Long.class),
                        resultSet.getObject("api_daily_quota", Long.class),
                        resultSet.getObject("api_monthly_quota", Long.class)
                );
                assertFalse(resultSet.next());
                return policy;
            }
        }
    }

    private static void insertRateLimitPolicy(
            UUID tenantId,
            String scopeType,
            UUID scopeId,
            long requests,
            int windowSeconds,
            int burst
    ) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO rate_limit_policy (
                         tenant_id,
                         scope_type,
                         scope_id,
                         limit_value,
                         window_seconds,
                         burst,
                         algorithm,
                         enabled
                     ) VALUES (?, ?, ?, ?, ?, ?, 'TOKEN_BUCKET', true)
                     """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, scopeType);
            statement.setObject(3, scopeId);
            statement.setLong(4, requests);
            statement.setInt(5, windowSeconds);
            statement.setInt(6, burst);
            statement.executeUpdate();
        }
    }

    private static void insertQuotaPolicy(
            UUID tenantId,
            String scopeType,
            UUID scopeId,
            String period,
            long limit
    ) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO quota_policy (
                         tenant_id,
                         scope_type,
                         scope_id,
                         period,
                         limit_value,
                         metric,
                         enabled
                     ) VALUES (?, ?, ?, ?, ?, 'CALLS', true)
                     """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, scopeType);
            statement.setObject(3, scopeId);
            statement.setString(4, period);
            statement.setLong(5, limit);
            statement.executeUpdate();
        }
    }

    private static Connection runtimeConnection() throws SQLException {
        Connection connection = dataSource.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET ROLE app_runtime");
        }
        return connection;
    }

    private static void createRuntimeRole() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
                            CREATE ROLE app_runtime NOLOGIN;
                        END IF;
                    END
                    $$;
                    GRANT USAGE ON SCHEMA public TO app_runtime;
                    GRANT EXECUTE
                        ON FUNCTION auth_authorize_public_api(text, text, text)
                        TO app_runtime;
                    GRANT EXECUTE
                        ON FUNCTION auth_resolve_post_auth_policies(uuid, uuid)
                        TO app_runtime;
                    """);
        }
    }

    private static void insertTenant(
            Connection connection,
            UUID tenantId,
            String suffix
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_tenant (id, code, name, status, auth_epoch)
                VALUES (?, ?, ?, 'ACTIVE', 1)
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, "authz-" + suffix);
            statement.setString(3, "authz-" + suffix);
            statement.executeUpdate();
        }
    }

    private static void insertUserAndRole(
            Connection connection,
            UUID tenantId,
            UUID userId,
            String suffix
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_user (id, email, password_hash, mfa_enabled, status)
                VALUES (?, ?, 'argon2-test-hash', false, 'ACTIVE')
                """)) {
            statement.setObject(1, userId);
            statement.setString(2, "authz-" + suffix + "@example.com");
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_role_binding (
                    tenant_id, user_id, role_code, scope_type
                ) VALUES (?, ?, 'APP_DEVELOPER', 'TENANT')
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, userId);
            statement.executeUpdate();
        }
    }

    private static void insertApp(
            Connection connection,
            UUID tenantId,
            UUID userId,
            UUID appId,
            String suffix
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app (
                    id, tenant_id, name, owner_user_id, status, auth_epoch
                ) VALUES (?, ?, ?, ?, 'ACTIVE', 1)
                """)) {
            statement.setObject(1, appId);
            statement.setObject(2, tenantId);
            statement.setString(3, "authz-app-" + suffix);
            statement.setObject(4, userId);
            statement.executeUpdate();
        }
    }

    private static void insertCredential(
            Connection connection,
            UUID tenantId,
            UUID appId,
            String appKey
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app_credential (
                    tenant_id, app_id, app_key, secret_ciphertext, kms_key_id,
                    status, auth_epoch
                ) VALUES (?, ?, ?, ?, 'test-kms', 'ACTIVE', 1)
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, appId);
            statement.setString(3, appKey);
            statement.setBytes(4, new byte[]{1, 2, 3});
            statement.executeUpdate();
        }
    }

    private static void insertApiDefinition(
            Connection connection,
            UUID tenantId,
            UUID userId,
            UUID apiId,
            String visibility,
            String publicPath
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_definition (
                    id, owner_tenant_id, code, name, public_method, public_path,
                    kind, visibility, status, publish_epoch
                ) VALUES (?, ?, ?, ?, 'GET', ?, 'PROXY', ?, 'PUBLISHED', 1)
                """)) {
            String suffix = apiId.toString().substring(0, 8);
            statement.setObject(1, apiId);
            statement.setObject(2, tenantId);
            statement.setString(3, "authz-api-" + suffix);
            statement.setString(4, "Authz API " + suffix);
            statement.setString(5, publicPath);
            statement.setString(6, visibility);
            statement.executeUpdate();
        }
    }

    private static void insertApiVersion(
            Connection connection,
            UUID apiId,
            UUID userId,
            UUID versionId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_version (
                    id, api_id, version, status, request_schema, response_schema,
                    timeout_ms, config_json, config_checksum, created_by
                ) VALUES (
                    ?, ?, 1, 'PUBLISHED', '{"type":"object"}'::jsonb,
                    '{"type":"object"}'::jsonb, 1000,
                    '{"upstreamEndpointId":"00000000-0000-0000-0000-000000000001"}'::jsonb,
                    repeat('a', 64), ?
                )
                """)) {
            statement.setObject(1, versionId);
            statement.setObject(2, apiId);
            statement.setObject(3, userId);
            statement.executeUpdate();
        }
    }

    private static void insertPublication(
            Connection connection,
            UUID publicationId,
            UUID apiId,
            UUID tenantId,
            UUID versionId,
            UUID userId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_publication (
                    id, api_id, owner_tenant_id, visibility, api_version_id,
                    environment, publication_no, status, manifest_json,
                    manifest_checksum, published_by
                )
                SELECT ?, api.id, api.owner_tenant_id, api.visibility, ?,
                       'PROD', 1, 'ACTIVE',
                       '{"requiredApis":[]}'::jsonb, repeat('b', 64), ?
                FROM api_definition AS api
                WHERE api.id = ?
                """)) {
            statement.setObject(1, publicationId);
            statement.setObject(2, versionId);
            statement.setObject(3, userId);
            statement.setObject(4, apiId);
            statement.executeUpdate();
        }
    }

    private static void activate(
            Connection connection,
            UUID apiId,
            UUID publicationId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE api_definition
                SET active_prod_publication_id = ?, publish_epoch = publish_epoch + 1
                WHERE id = ?
                """)) {
            statement.setObject(1, publicationId);
            statement.setObject(2, apiId);
            statement.executeUpdate();
        }
    }

    private static void insertGrant(
            Connection connection,
            FixtureIdentity caller,
            UUID apiId,
            String status
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app_api_grant (
                    tenant_id, app_id, api_id, granted_by, status, auth_epoch
                ) VALUES (?, ?, ?, ?, ?, 1)
                """)) {
            statement.setObject(1, caller.tenantId());
            statement.setObject(2, caller.appId());
            statement.setObject(3, apiId);
            statement.setObject(4, caller.userId());
            statement.setString(5, status);
            statement.executeUpdate();
        }
    }

    private record FixtureIdentity(
            UUID tenantId,
            UUID userId,
            UUID appId,
            String appKey
    ) {
    }

    private record Fixture(
            String appKey,
            UUID tenantId,
            UUID appId,
            UUID apiId,
            UUID apiVersionId,
            String path
    ) {
    }

    private record Decision(
            String code,
            UUID appId,
            UUID apiId,
            UUID apiVersionId,
            String visibility
    ) {
    }

    private record EffectivePolicy(
            Long appRateRequests,
            Integer appRateWindowSeconds,
            Integer appRateBurst,
            Long apiRateRequests,
            Integer apiRateWindowSeconds,
            Integer apiRateBurst,
            Long appDailyQuota,
            Long appMonthlyQuota,
            Long apiDailyQuota,
            Long apiMonthlyQuota
    ) {
    }
}
