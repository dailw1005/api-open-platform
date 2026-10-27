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
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseFoundationTest {

    private static final Set<String> FOUNDATION_TABLES = Set.of(
            "iam_tenant",
            "iam_user",
            "iam_role_binding",
            "iam_session",
            "app",
            "app_credential",
            "app_api_grant",
            "upstream_endpoint",
            "upstream_environment",
            "api_definition",
            "api_version",
            "api_publication",
            "rate_limit_policy",
            "quota_policy",
            "orchestration",
            "orchestration_version",
            "idempotency_record",
            "outbox_event"
    );

    private static final Set<String> RLS_TABLES = Set.of(
            "iam_tenant",
            "iam_role_binding",
            "app",
            "app_credential",
            "app_api_grant",
            "rate_limit_policy",
            "quota_policy",
            "orchestration",
            "orchestration_version",
            "idempotency_record",
            "outbox_event"
    );

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
    void createsFoundationTables() throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT table_name
                     FROM information_schema.tables
                     WHERE table_schema = 'public'
                     """)) {
            Set<String> actual = new HashSet<>();
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    actual.add(resultSet.getString(1));
                }
            }
            assertTrue(actual.containsAll(FOUNDATION_TABLES),
                    () -> "Missing tables: " + difference(FOUNDATION_TABLES, actual));
        }
    }

    @Test
    void enablesRowLevelSecurityOnTenantTables() throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT relname, relrowsecurity
                     FROM pg_class
                     WHERE relname = ANY (?)
                     """)) {
            statement.setArray(
                    1,
                    connection.createArrayOf("text", RLS_TABLES.toArray())
            );
            Set<String> secured = new HashSet<>();
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    if (resultSet.getBoolean(2)) {
                        secured.add(resultSet.getString(1));
                    }
                }
            }
            assertTrue(secured.containsAll(RLS_TABLES),
                    () -> "RLS missing on: " + difference(RLS_TABLES, secured));
        }
    }

    @Test
    void rejectsCrossTenantCompositeForeignKey() throws Exception {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID app = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenantA, "tenant-a");
            insertTenant(connection, tenantB, "tenant-b");
            insertUserAndRole(connection, tenantA, user, "owner@example.com", "APP_DEVELOPER");
            insertApp(connection, tenantA, user, app, "orders-app");

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertCredential(
                            connection,
                            tenantB,
                            app,
                            "ak_cross_tenant_1234567890"
                    )
            );

            assertEquals("23503", exception.getSQLState());
        }
    }

    @Test
    void rowLevelSecurityFiltersAndRejectsOtherTenants() throws Exception {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        UUID userA = UUID.randomUUID();
        UUID userB = UUID.randomUUID();
        UUID appA = UUID.randomUUID();
        UUID appA2 = UUID.randomUUID();
        UUID appB = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenantA, "rls-a");
            insertTenant(connection, tenantB, "rls-b");
            insertUserAndRole(connection, tenantA, userA, "rls-a@example.com", "APP_DEVELOPER");
            insertUserAndRole(connection, tenantB, userB, "rls-b@example.com", "APP_DEVELOPER");
            insertApp(connection, tenantA, userA, appA, "app-a-1");
            insertApp(connection, tenantA, userA, appA2, "app-a-2");
            insertApp(connection, tenantB, userB, appB, "app-b");
        }

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET LOCAL ROLE app_runtime");
                statement.execute(
                        "SELECT set_config('app.tenant_id', '" + tenantA + "', true)"
                );
            }

            try (Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery("SELECT count(*) FROM app")) {
                resultSet.next();
                assertEquals(2, resultSet.getInt(1));
            }

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertApp(
                            connection,
                            tenantB,
                            userB,
                            UUID.randomUUID(),
                            "cross-tenant"
                    )
            );
            assertEquals("42501", exception.getSQLState());
            connection.rollback();
        }
    }

    @Test
    void activatesMatchingActiveProductionPublication() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();
        UUID publication = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "active-publication");
            insertUserAndRole(connection, tenant, user, "active@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "active-api", "/v1/active");
            insertApiVersion(connection, api, user, version);
            insertPublicationWithId(
                    connection,
                    publication,
                    api,
                    tenant,
                    version,
                    user,
                    "PROD",
                    "ACTIVE",
                    1
            );

            activatePublication(connection, api, publication);

            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT active_prod_publication_id
                    FROM api_definition
                    WHERE id = ?
                    """)) {
                statement.setObject(1, api);
                try (ResultSet resultSet = statement.executeQuery()) {
                    resultSet.next();
                    assertEquals(publication, resultSet.getObject(1, UUID.class));
                }
            }
        }
    }

    @Test
    void rejectsMultipleActivePublicationsForOneApi() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "single-active");
            insertUserAndRole(connection, tenant, user, "single@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "single-api", "/v1/single");
            insertApiVersion(connection, api, user, version);
            insertPublication(
                    connection,
                    api,
                    tenant,
                    version,
                    user,
                    "PROD",
                    "ACTIVE",
                    1
            );

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertPublication(
                            connection,
                            api,
                            tenant,
                            version,
                            user,
                            "PROD",
                            "ACTIVE",
                            2
                    )
            );
            assertEquals("23505", exception.getSQLState());
        }
    }

    @Test
    void cannotRevokePublicationWhileActivePointerReferencesIt() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();
        UUID publication = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "revoke-active");
            insertUserAndRole(connection, tenant, user, "revoke@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "revoke-api", "/v1/revoke");
            insertApiVersion(connection, api, user, version);
            insertPublicationWithId(
                    connection,
                    publication,
                    api,
                    tenant,
                    version,
                    user,
                    "PROD",
                    "ACTIVE",
                    1
            );
            activatePublication(connection, api, publication);

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> revokePublication(connection, publication)
            );
            assertEquals("23514", exception.getSQLState());
        }
    }

    @Test
    void cannotCommitSupersededPublicationWhileStillActive() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();
        UUID publication = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "supersede-active");
            insertUserAndRole(connection, tenant, user, "supersede@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "supersede-api", "/v1/supersede");
            insertApiVersion(connection, api, user, version);
            insertPublicationWithId(
                    connection,
                    publication,
                    api,
                    tenant,
                    version,
                    user,
                    "PROD",
                    "ACTIVE",
                    1
            );
            activatePublication(connection, api, publication);

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> supersedePublication(connection, publication)
            );
            assertEquals("23514", exception.getSQLState());
        }
    }

    @Test
    void rejectsNonProductionPublication() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "pub-non-prod");
            insertUserAndRole(connection, tenant, user, "pub@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "pub-api", "/v1/pub");
            insertApiVersion(connection, api, user, version);

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertPublication(
                            connection,
                            api,
                            tenant,
                            version,
                            user,
                            "SANDBOX",
                            "PREPARED",
                            1
                    )
            );
            assertEquals("23514", exception.getSQLState());
        }
    }

    @Test
    void activePointerCannotReferenceRevokedPublication() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        UUID api = UUID.randomUUID();
        UUID version = UUID.randomUUID();
        UUID publication = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "revoked-publication");
            insertUserAndRole(connection, tenant, user, "revoked@example.com", "APP_DEVELOPER");
            insertApiDefinition(connection, tenant, api, "revoked-api", "/v1/revoked");
            insertApiVersion(connection, api, user, version);
            insertPublicationWithId(
                    connection,
                    publication,
                    api,
                    tenant,
                    version,
                    user,
                    "PROD",
                    "REVOKED",
                    1
            );

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> activatePublication(connection, api, publication)
            );
            assertEquals("23514", exception.getSQLState());
        }
    }

    @Test
    void adminSessionStoresOnlyHashesAndCanBeRevoked() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        String sessionHash = "a".repeat(64);
        String csrfHash = "b".repeat(64);

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "admin-session");
            insertUserAndRole(
                    connection,
                    tenant,
                    user,
                    "admin-session@example.com",
                    "PLATFORM_ADMIN"
            );

            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO iam_session (
                        token_hash, user_id, csrf_token_hash, expires_at
                    ) VALUES (?, ?, ?, now() + interval '8 hours')
                    """)) {
                statement.setString(1, sessionHash);
                statement.setObject(2, user);
                statement.setString(3, csrfHash);
                assertEquals(1, statement.executeUpdate());
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT user_id, csrf_token_hash, revoked_at
                    FROM iam_session
                    WHERE token_hash = ?
                    """)) {
                statement.setString(1, sessionHash);
                try (ResultSet resultSet = statement.executeQuery()) {
                    assertTrue(resultSet.next());
                    assertEquals(user, resultSet.getObject(1, UUID.class));
                    assertEquals(csrfHash, resultSet.getString(2));
                    assertEquals(null, resultSet.getObject(3));
                    assertTrue(!resultSet.next());
                }
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE iam_session
                    SET revoked_at = now()
                    WHERE token_hash = ? AND revoked_at IS NULL
                    """)) {
                statement.setString(1, sessionHash);
                assertEquals(1, statement.executeUpdate());
                assertEquals(0, statement.executeUpdate());
            }
        }
    }

    @Test
    void adminSessionRejectsMalformedHashesAndExpiredLifetime() throws Exception {
        UUID tenant = UUID.randomUUID();
        UUID user = UUID.randomUUID();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenant, "admin-session-invalid");
            insertUserAndRole(
                    connection,
                    tenant,
                    user,
                    "admin-session-invalid@example.com",
                    "PLATFORM_ADMIN"
            );

            SQLException malformedHash = assertThrows(
                    SQLException.class,
                    () -> insertAdminSession(
                            connection,
                            "raw-session-token",
                            user,
                            "b".repeat(64),
                            "8 hours"
                    )
            );
            assertEquals("23514", malformedHash.getSQLState());

            SQLException expired = assertThrows(
                    SQLException.class,
                    () -> insertAdminSession(
                            connection,
                            "c".repeat(64),
                            user,
                            "d".repeat(64),
                            "-1 second"
                    )
            );
            assertEquals("23514", expired.getSQLState());
        }
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
                    GRANT SELECT, INSERT, UPDATE, DELETE
                        ON ALL TABLES IN SCHEMA public TO app_runtime;
                    """);
        }
    }

    private static void insertTenant(Connection connection, UUID id, String code)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_tenant (id, code, name, status)
                VALUES (?, ?, ?, 'ACTIVE')
                """)) {
            statement.setObject(1, id);
            statement.setString(2, code);
            statement.setString(3, code);
            statement.executeUpdate();
        }
    }

    private static void insertUserAndRole(
            Connection connection,
            UUID tenant,
            UUID user,
            String email,
            String role
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_user (id, email, password_hash, mfa_enabled, status)
                VALUES (?, ?, 'argon2-test-hash', false, 'ACTIVE')
                """)) {
            statement.setObject(1, user);
            statement.setString(2, email);
            statement.executeUpdate();
        }
        String scopeType = "PLATFORM_ADMIN".equals(role) ? "GLOBAL" : "TENANT";
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_role_binding (
                    tenant_id, user_id, role_code, scope_type
                ) VALUES (?, ?, ?, ?)
                """)) {
            statement.setObject(1, tenant);
            statement.setObject(2, user);
            statement.setString(3, role);
            statement.setString(4, scopeType);
            statement.executeUpdate();
        }
    }

    private static void insertApp(
            Connection connection,
            UUID tenant,
            UUID owner,
            UUID app,
            String name
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app (
                    id, tenant_id, name, owner_user_id, status, auth_epoch
                ) VALUES (?, ?, ?, ?, 'ACTIVE', 1)
                """)) {
            statement.setObject(1, app);
            statement.setObject(2, tenant);
            statement.setString(3, name);
            statement.setObject(4, owner);
            statement.executeUpdate();
        }
    }

    private static void insertCredential(
            Connection connection,
            UUID tenant,
            UUID app,
            String appKey
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app_credential (
                    tenant_id, app_id, app_key, secret_ciphertext, kms_key_id,
                    status, auth_epoch
                ) VALUES (?, ?, ?, ?, 'test-kms', 'ACTIVE', 1)
                """)) {
            statement.setObject(1, tenant);
            statement.setObject(2, app);
            statement.setString(3, appKey);
            statement.setBytes(4, new byte[]{1, 2, 3});
            statement.executeUpdate();
        }
    }

    private static void insertAdminSession(
            Connection connection,
            String tokenHash,
            UUID userId,
            String csrfTokenHash,
            String lifetime
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_session (
                    token_hash, user_id, csrf_token_hash, expires_at
                ) VALUES (?, ?, ?, now() + ?::interval)
                """)) {
            statement.setString(1, tokenHash);
            statement.setObject(2, userId);
            statement.setString(3, csrfTokenHash);
            statement.setString(4, lifetime);
            statement.executeUpdate();
        }
    }

    private static void insertApiDefinition(
            Connection connection,
            UUID tenant,
            UUID api,
            String code,
            String path
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_definition (
                    id, owner_tenant_id, code, name, public_method, public_path,
                    kind, visibility, status, publish_epoch
                ) VALUES (?, ?, ?, ?, 'GET', ?, 'PROXY', 'TENANT_PRIVATE', 'PUBLISHED', 1)
                """)) {
            statement.setObject(1, api);
            statement.setObject(2, tenant);
            statement.setString(3, code);
            statement.setString(4, code);
            statement.setString(5, path);
            statement.executeUpdate();
        }
    }

    private static void insertApiVersion(
            Connection connection,
            UUID api,
            UUID createdBy,
            UUID version
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_version (
                    id, api_id, version, status, request_schema, response_schema,
                    timeout_ms, config_json, config_checksum, created_by
                ) VALUES (
                    ?, ?, 1, 'PUBLISHED', '{"type":"object"}'::jsonb, '{"type":"object"}'::jsonb,
                    1000, '{"upstreamEndpointId":"00000000-0000-0000-0000-000000000001"}'::jsonb,
                    repeat('a', 64), ?
                )
                """)) {
            statement.setObject(1, version);
            statement.setObject(2, api);
            statement.setObject(3, createdBy);
            statement.executeUpdate();
        }
    }

    private static void insertPublication(
            Connection connection,
            UUID api,
            UUID tenant,
            UUID version,
            UUID publishedBy,
            String environment,
            String status,
            int publicationNo
    ) throws SQLException {
        insertPublicationWithId(
                connection,
                UUID.randomUUID(),
                api,
                tenant,
                version,
                publishedBy,
                environment,
                status,
                publicationNo
        );
    }

    private static void insertPublicationWithId(
            Connection connection,
            UUID publication,
            UUID api,
            UUID tenant,
            UUID version,
            UUID publishedBy,
            String environment,
            String status,
            int publicationNo
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO api_publication (
                    id, api_id, owner_tenant_id, visibility, api_version_id,
                    environment, publication_no, status, manifest_json,
                    manifest_checksum, published_by
                ) VALUES (
                    ?, ?, ?, 'TENANT_PRIVATE', ?, ?, ?, ?,
                    '{"requiredApis":[]}'::jsonb, repeat('b', 64), ?
                )
                """)) {
            statement.setObject(1, publication);
            statement.setObject(2, api);
            statement.setObject(3, tenant);
            statement.setObject(4, version);
            statement.setString(5, environment);
            statement.setInt(6, publicationNo);
            statement.setString(7, status);
            statement.setObject(8, publishedBy);
            statement.executeUpdate();
        }
    }

    private static void activatePublication(
            Connection connection,
            UUID api,
            UUID publication
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE api_definition
                SET active_prod_publication_id = ?, publish_epoch = publish_epoch + 1
                WHERE id = ?
                """)) {
            statement.setObject(1, publication);
            statement.setObject(2, api);
            statement.executeUpdate();
        }
    }

    private static void revokePublication(Connection connection, UUID publication)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE api_publication
                SET status = 'REVOKED'
                WHERE id = ?
                """)) {
            statement.setObject(1, publication);
            statement.executeUpdate();
        }
    }

    private static void supersedePublication(Connection connection, UUID publication)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE api_publication
                SET status = 'SUPERSEDED'
                WHERE id = ?
                """)) {
            statement.setObject(1, publication);
            statement.executeUpdate();
        }
    }

    private static Set<String> difference(Set<String> expected, Set<String> actual) {
        Set<String> missing = new HashSet<>(expected);
        missing.removeAll(actual);
        return missing;
    }
}
