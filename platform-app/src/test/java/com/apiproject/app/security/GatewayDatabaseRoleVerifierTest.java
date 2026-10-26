package com.apiproject.app.security;

import com.apiproject.gateway.security.CredentialResolutionException;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayDatabaseRoleVerifierTest {

    private static EmbeddedPostgres postgres;
    private static DataSource adminDataSource;
    private static String jdbcUrl;

    @BeforeAll
    static void migrateDatabase() throws Exception {
        postgres = EmbeddedPostgres.builder().start();
        adminDataSource = postgres.getPostgresDatabase();
        jdbcUrl = postgres.getJdbcUrl("postgres", "postgres");
        Flyway.configure()
                .dataSource(adminDataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    @AfterAll
    static void closeDatabase() throws Exception {
        if (postgres != null) {
            postgres.close();
        }
    }

    @Test
    void acceptsLeastPrivilegeGatewayRole() throws Exception {
        createRole("gateway_least_privilege", "LOGIN PASSWORD 'test-password'");
        grantFunctionOnly("gateway_least_privilege");

        GatewayDatabaseRoleVerifier verifier = verifierFor("gateway_least_privilege");

        GatewayDatabaseRoleStatus status = assertDoesNotThrow(verifier::verify);
        assertEquals("gateway_least_privilege", status.roleName());
        assertTrue(status.credentialFunctionExecute());
        assertTrue(status.authorizationFunctionExecute());
        assertTrue(status.policyFunctionExecute());
    }

    @Test
    void rejectsGatewayRoleWithDirectCredentialTableAccess() throws Exception {
        createRole("gateway_table_access", "LOGIN PASSWORD 'test-password'");
        grantFunctionOnly("gateway_table_access");
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(
                    "GRANT SELECT ON app_credential TO gateway_table_access"
            );
        }

        GatewayDatabaseRoleVerifier verifier = verifierFor("gateway_table_access");

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                verifier::verify
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(exception.getMessage().contains("sensitive table privileges"));
    }

    @Test
    void rejectsSuperuserGatewayRole() throws Exception {
        createRole("gateway_superuser", "LOGIN SUPERUSER PASSWORD 'test-password'");

        GatewayDatabaseRoleVerifier verifier = verifierFor("gateway_superuser");

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                verifier::verify
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(exception.getMessage().contains("superuser"));
    }

    @Test
    void rejectsBypassRlsGatewayRole() throws Exception {
        createRole(
                "gateway_bypass_rls",
                "LOGIN BYPASSRLS PASSWORD 'test-password'"
        );
        grantFunctionOnly("gateway_bypass_rls");

        GatewayDatabaseRoleVerifier verifier = verifierFor("gateway_bypass_rls");

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                verifier::verify
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(exception.getMessage().contains("BYPASSRLS"));
    }

    @Test
    void rejectsGatewayRoleWithoutFunctionExecute() throws Exception {
        createRole(
                "gateway_no_function",
                "LOGIN PASSWORD 'test-password'"
        );
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(
                    "GRANT CONNECT ON DATABASE postgres TO gateway_no_function"
            );
            statement.execute(
                    "GRANT USAGE ON SCHEMA public TO gateway_no_function"
            );
        }

        GatewayDatabaseRoleVerifier verifier = verifierFor("gateway_no_function");

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                verifier::verify
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(exception.getMessage().contains("EXECUTE"));
    }

    @Test
    void rejectsGatewayRoleWithoutPostAuthPolicyExecute() throws Exception {
        createRole(
                "gateway_no_policy_function",
                "LOGIN PASSWORD 'test-password'"
        );
        grantAuthenticationFunctionsWithoutPolicy("gateway_no_policy_function");

        GatewayDatabaseRoleVerifier verifier =
                verifierFor("gateway_no_policy_function");

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                verifier::verify
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(exception.getMessage().contains("policy"));
    }

    private static void createRole(String roleName, String attributes)
            throws SQLException {
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("DROP ROLE IF EXISTS " + roleName);
            statement.execute("CREATE ROLE " + roleName + " " + attributes);
        }
    }

    private static void grantFunctionOnly(String roleName) throws SQLException {
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("GRANT CONNECT ON DATABASE postgres TO " + roleName);
            statement.execute("GRANT USAGE ON SCHEMA public TO " + roleName);
            statement.execute(
                    "GRANT EXECUTE ON FUNCTION auth_resolve_active_credential(text) "
                            + "TO " + roleName
            );
            statement.execute(
                    "GRANT EXECUTE ON FUNCTION "
                            + "auth_authorize_public_api(text,text,text) "
                            + "TO " + roleName
            );
            statement.execute(
                    "GRANT EXECUTE ON FUNCTION "
                            + "auth_resolve_post_auth_policies(uuid,uuid) "
                            + "TO " + roleName
            );
        }
    }

    private static void grantAuthenticationFunctionsWithoutPolicy(
            String roleName
    ) throws SQLException {
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("GRANT CONNECT ON DATABASE postgres TO " + roleName);
            statement.execute("GRANT USAGE ON SCHEMA public TO " + roleName);
            statement.execute(
                    "GRANT EXECUTE ON FUNCTION auth_resolve_active_credential(text) "
                            + "TO " + roleName
            );
            statement.execute(
                    "GRANT EXECUTE ON FUNCTION "
                            + "auth_authorize_public_api(text,text,text) "
                            + "TO " + roleName
            );
        }
    }

    private static GatewayDatabaseRoleVerifier verifierFor(String userName) {
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setUrl(jdbcUrl);
        dataSource.setUser(userName);
        dataSource.setPassword("test-password");
        return new GatewayDatabaseRoleVerifier(dataSource);
    }
}
