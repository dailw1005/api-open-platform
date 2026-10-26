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
import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActiveCredentialLookupTest {

    private static final String FUNCTION_CALL = """
            SELECT credential_id, tenant_id, app_id, kms_key_id,
                   secret_ciphertext, app_auth_epoch, credential_auth_epoch
            FROM auth_resolve_active_credential(?)
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
    void activeCredentialCanBeResolvedWithoutTenantContext() throws Exception {
        Fixture fixture = insertFixture("ACTIVE", "ACTIVE", null, "ACTIVE");

        try (Connection connection = runtimeConnection();
             PreparedStatement statement = connection.prepareStatement(FUNCTION_CALL)) {
            statement.setString(1, fixture.appKey());
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals(fixture.credentialId(), resultSet.getObject(1, UUID.class));
                assertEquals(fixture.tenantId(), resultSet.getObject(2, UUID.class));
                assertEquals(fixture.appId(), resultSet.getObject(3, UUID.class));
                assertEquals("test-kms", resultSet.getString(4));
                assertArrayEquals(
                        fixture.ciphertext(),
                        resultSet.getBytes(5)
                );
                assertEquals(1L, resultSet.getLong(6));
                assertEquals(1L, resultSet.getLong(7));
                assertFalse(resultSet.next());
            }
        }
    }

    @Test
    void rotatingCredentialRemainsAvailableForOverlap() throws Exception {
        Fixture fixture = insertFixture(
                "ACTIVE",
                "ACTIVE",
                OffsetDateTime.now().plusMinutes(5),
                "ROTATING"
        );

        try (Connection connection = runtimeConnection();
             PreparedStatement statement = connection.prepareStatement(FUNCTION_CALL)) {
            statement.setString(1, fixture.appKey());
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals(fixture.credentialId(), resultSet.getObject(1, UUID.class));
            }
        }
    }

    @Test
    void inactiveOwnersAndExpiredCredentialReturnNoRows() throws Exception {
        Fixture suspendedTenant = insertFixture(
                "SUSPENDED",
                "ACTIVE",
                null,
                "ACTIVE"
        );
        Fixture suspendedApp = insertFixture(
                "ACTIVE",
                "SUSPENDED",
                null,
                "ACTIVE"
        );
        Fixture revokedCredential = insertFixture(
                "ACTIVE",
                "ACTIVE",
                null,
                "REVOKED"
        );
        Fixture expiredCredential = insertFixture(
                "ACTIVE",
                "ACTIVE",
                OffsetDateTime.now().minusMinutes(1),
                "ACTIVE"
        );

        assertFalse(resolve(suspendedTenant.appKey()));
        assertFalse(resolve(suspendedApp.appKey()));
        assertFalse(resolve(revokedCredential.appKey()));
        assertFalse(resolve(expiredCredential.appKey()));
    }

    private static boolean resolve(String appKey) throws SQLException {
        try (Connection connection = runtimeConnection();
             PreparedStatement statement = connection.prepareStatement(FUNCTION_CALL)) {
            statement.setString(1, appKey);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next();
            }
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
                    GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_runtime;
                    GRANT EXECUTE
                        ON FUNCTION auth_resolve_active_credential(text)
                        TO app_runtime;
                    """);
        }
    }

    private static Fixture insertFixture(
            String tenantStatus,
            String appStatus,
            OffsetDateTime expiresAt,
            String credentialStatus
    ) throws SQLException {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        UUID appId = UUID.randomUUID();
        UUID credentialId = UUID.randomUUID();
        String suffix = tenantId.toString().substring(0, 8);
        String appKey = "ak_credential_" + suffix + "_123456";
        byte[] ciphertext = ("ciphertext-" + suffix).getBytes();

        try (Connection connection = dataSource.getConnection()) {
            insertTenant(connection, tenantId, "tenant-" + suffix, tenantStatus);
            insertUserAndRole(connection, tenantId, userId, "owner-" + suffix + "@example.com");
            insertApp(connection, tenantId, userId, appId, "app-" + suffix, appStatus);
            insertCredential(
                    connection,
                    credentialId,
                    tenantId,
                    appId,
                    appKey,
                    ciphertext,
                    credentialStatus,
                    expiresAt
            );
        }

        return new Fixture(
                tenantId,
                appId,
                credentialId,
                appKey,
                ciphertext
        );
    }

    private static void insertTenant(
            Connection connection,
            UUID tenantId,
            String code,
            String status
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_tenant (id, code, name, status, auth_epoch)
                VALUES (?, ?, ?, ?, 1)
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, code);
            statement.setString(3, code);
            statement.setString(4, status);
            statement.executeUpdate();
        }
    }

    private static void insertUserAndRole(
            Connection connection,
            UUID tenantId,
            UUID userId,
            String email
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO iam_user (id, email, password_hash, mfa_enabled, status)
                VALUES (?, ?, 'argon2-test-hash', false, 'ACTIVE')
                """)) {
            statement.setObject(1, userId);
            statement.setString(2, email);
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
            String name,
            String status
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app (
                    id, tenant_id, name, owner_user_id, status, auth_epoch
                ) VALUES (?, ?, ?, ?, ?, 1)
                """)) {
            statement.setObject(1, appId);
            statement.setObject(2, tenantId);
            statement.setString(3, name);
            statement.setObject(4, userId);
            statement.setString(5, status);
            statement.executeUpdate();
        }
    }

    private static void insertCredential(
            Connection connection,
            UUID credentialId,
            UUID tenantId,
            UUID appId,
            String appKey,
            byte[] ciphertext,
            String status,
            OffsetDateTime expiresAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO app_credential (
                    id, tenant_id, app_id, app_key, secret_ciphertext, kms_key_id,
                    status, auth_epoch, expires_at
                ) VALUES (?, ?, ?, ?, ?, 'test-kms', ?, 1, ?)
                """)) {
            statement.setObject(1, credentialId);
            statement.setObject(2, tenantId);
            statement.setObject(3, appId);
            statement.setString(4, appKey);
            statement.setBytes(5, ciphertext);
            statement.setString(6, status);
            statement.setObject(7, expiresAt);
            statement.executeUpdate();
        }
    }

    private record Fixture(
            UUID tenantId,
            UUID appId,
            UUID credentialId,
            String appKey,
            byte[] ciphertext
    ) {
    }
}
