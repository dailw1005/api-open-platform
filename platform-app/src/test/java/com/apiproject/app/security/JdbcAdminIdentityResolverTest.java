package com.apiproject.app.security;

import com.apiproject.control.iam.AdminAuthenticationException;
import com.apiproject.control.iam.AdminIdentity;
import com.apiproject.control.iam.AdminLoginIdentity;
import com.apiproject.control.iam.SessionRoleBinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcAdminIdentityResolverTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final UUID ROLE_ID = UUID.randomUUID();

    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement userStatement;
    private PreparedStatement roleStatement;
    private ResultSet userResult;
    private ResultSet roleResult;
    private JdbcAdminIdentityResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        userStatement = mock(PreparedStatement.class);
        roleStatement = mock(PreparedStatement.class);
        userResult = mock(ResultSet.class);
        roleResult = mock(ResultSet.class);
        resolver = new JdbcAdminIdentityResolver(dataSource);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString()))
                .thenReturn(userStatement, roleStatement);
        when(userStatement.executeQuery()).thenReturn(userResult);
        when(roleStatement.executeQuery()).thenReturn(roleResult);
    }

    @Test
    void resolvesActiveAdminLoginIdentityAndRoleBindings() throws Exception {
        when(userResult.next()).thenReturn(true, false);
        when(userResult.getObject("id", UUID.class)).thenReturn(USER_ID);
        when(userResult.getString("email"))
                .thenReturn("admin@example.com");
        when(userResult.getString("display_name")).thenReturn("Administrator");
        when(userResult.getString("password_hash")).thenReturn("argon2-hash");
        when(userResult.getBoolean("mfa_enabled")).thenReturn(false);

        when(roleResult.next()).thenReturn(true, true, false);
        when(roleResult.getObject("id", UUID.class))
                .thenReturn(ROLE_ID, UUID.randomUUID());
        when(roleResult.getObject("user_id", UUID.class))
                .thenReturn(USER_ID);
        when(roleResult.getObject("tenant_id", UUID.class))
                .thenReturn(TENANT_ID, UUID.randomUUID());
        when(roleResult.getString("role_code"))
                .thenReturn("PLATFORM_ADMIN", "VIEWER");
        when(roleResult.getString("scope_type"))
                .thenReturn("GLOBAL", "TENANT");

        Optional<AdminLoginIdentity> found =
                resolver.findByEmail("admin@example.com");

        assertTrue(found.isPresent());
        AdminIdentity identity = found.orElseThrow().identity();
        assertEquals(USER_ID, identity.userId());
        assertEquals("admin@example.com", identity.email());
        assertEquals("Administrator", identity.displayName());
        assertEquals("argon2-hash", found.orElseThrow().passwordHash());
        assertFalse(found.orElseThrow().mfaEnabled());
        assertEquals(2, identity.roles().size());
        assertTrue(identity.hasGlobalPlatformAdmin());
    }

    @Test
    void resolvesIdentityByUserIdWithSameRoleSet() throws Exception {
        stubUser();
        stubRole();

        Optional<AdminIdentity> found = resolver.findByUserId(USER_ID);

        assertTrue(found.isPresent());
        assertEquals(USER_ID, found.orElseThrow().userId());
        assertEquals(1, found.orElseThrow().roles().size());
    }

    @Test
    void unknownActiveUserReturnsEmpty() throws Exception {
        when(userResult.next()).thenReturn(false);

        assertTrue(resolver.findByEmail("missing@example.com").isEmpty());
        assertTrue(resolver.findByUserId(UUID.randomUUID()).isEmpty());
    }

    @Test
    void malformedIdentityRowsFailClosed() throws Exception {
        when(userResult.next()).thenReturn(true, false);
        when(userResult.getObject("id", UUID.class)).thenReturn(USER_ID);
        when(userResult.getString("email")).thenReturn(null);

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertFalse(exception.retryable());
    }

    @Test
    void blankDisplayNameFailsClosed() throws Exception {
        stubUser();
        when(userResult.getString("display_name")).thenReturn(" ");

        assertInternalConfigurationForEmailLookup();
    }

    @Test
    void overlongDisplayNameFailsClosed() throws Exception {
        stubUser();
        when(userResult.getString("display_name")).thenReturn("x".repeat(101));

        assertInternalConfigurationForEmailLookup();
    }

    @Test
    void blankPasswordHashFailsClosed() throws Exception {
        stubUser();
        when(userResult.getString("password_hash")).thenReturn(" ");

        assertInternalConfigurationForEmailLookup();
    }

    @Test
    void roleOwnedByAnotherUserFailsClosed() throws Exception {
        stubUser();
        when(roleResult.next()).thenReturn(true, false);
        when(roleResult.getObject("id", UUID.class))
                .thenReturn(ROLE_ID);
        when(roleResult.getObject("user_id", UUID.class))
                .thenReturn(UUID.randomUUID());
        when(roleResult.getObject("tenant_id", UUID.class))
                .thenReturn(TENANT_ID);
        when(roleResult.getString("role_code"))
                .thenReturn("PLATFORM_ADMIN");
        when(roleResult.getString("scope_type")).thenReturn("GLOBAL");

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByUserId(USER_ID)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void databaseFailureIsRetryableStoreUnavailable() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("down"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );

        assertEquals("IDENTITY_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void blankEmailAndNullUserIdAreRejectedBeforeQuerying() {
        assertThrows(
                IllegalArgumentException.class,
                () -> resolver.findByEmail(null)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> resolver.findByEmail(" ")
        );
        assertThrows(
                NullPointerException.class,
                () -> resolver.findByUserId(null)
        );
    }

    @Test
    void findByUserIdDatabaseFailureIsRetryable() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("down"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByUserId(USER_ID)
        );

        assertEquals("IDENTITY_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void multipleUserRowsFailClosed() throws Exception {
        stubUser();
        when(userResult.next()).thenReturn(true, true);

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void roleReadFailureFailsClosed() throws Exception {
        stubUser();
        when(roleResult.next()).thenReturn(true);
        when(roleResult.getObject("user_id", UUID.class))
                .thenThrow(new SQLException("bad role"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void unknownRoleCodeFailsClosed() throws Exception {
        stubUser();
        when(roleResult.next()).thenReturn(true, false);
        when(roleResult.getObject("id", UUID.class)).thenReturn(ROLE_ID);
        when(roleResult.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(roleResult.getObject("tenant_id", UUID.class))
                .thenReturn(TENANT_ID);
        when(roleResult.getString("role_code")).thenReturn("OWNER");
        when(roleResult.getString("scope_type")).thenReturn("GLOBAL");

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    private void stubUser() throws Exception {
        when(userResult.next()).thenReturn(true, false);
        when(userResult.getObject("id", UUID.class)).thenReturn(USER_ID);
        when(userResult.getString("email"))
                .thenReturn("admin@example.com");
        when(userResult.getString("display_name")).thenReturn("Administrator");
        when(userResult.getString("password_hash")).thenReturn("argon2-hash");
        when(userResult.getBoolean("mfa_enabled")).thenReturn(false);
    }

    private void stubRole() throws Exception {
        when(roleResult.next()).thenReturn(true, false);
        when(roleResult.getObject("id", UUID.class)).thenReturn(ROLE_ID);
        when(roleResult.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(roleResult.getObject("tenant_id", UUID.class))
                .thenReturn(TENANT_ID);
        when(roleResult.getString("role_code"))
                .thenReturn("PLATFORM_ADMIN");
        when(roleResult.getString("scope_type")).thenReturn("GLOBAL");
    }

    private void assertInternalConfigurationForEmailLookup() {
        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> resolver.findByEmail("admin@example.com")
        );
        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }
}
