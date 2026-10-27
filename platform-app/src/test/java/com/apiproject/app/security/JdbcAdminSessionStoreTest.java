package com.apiproject.app.security;

import com.apiproject.control.iam.AdminAuthenticationException;
import com.apiproject.control.iam.AdminSession;
import com.apiproject.control.iam.AdminSessionState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcAdminSessionStoreTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final Instant EXPIRES_AT =
            Instant.parse("2026-10-27T10:00:00Z");
    private static final String SESSION_HASH = "a".repeat(64);
    private static final String CSRF_HASH = "b".repeat(64);

    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement statement;
    private JdbcAdminSessionStore store;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        store = new JdbcAdminSessionStore(dataSource);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
    }

    @Test
    void createPersistsOnlyHashedSessionAndCsrfValues() throws Exception {
        when(statement.executeUpdate()).thenReturn(1);

        store.create(
                SESSION_HASH,
                new AdminSessionState(USER_ID, CSRF_HASH, EXPIRES_AT)
        );

        verify(statement).setString(1, SESSION_HASH);
        verify(statement).setObject(2, USER_ID);
        verify(statement).setString(3, CSRF_HASH);
        verify(statement).setTimestamp(4, Timestamp.from(EXPIRES_AT));
        verify(statement).executeUpdate();
    }

    @Test
    void findMapsAnActiveSession() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(resultSet.getString("csrf_token_hash")).thenReturn(CSRF_HASH);
        when(resultSet.getTimestamp("expires_at"))
                .thenReturn(Timestamp.from(EXPIRES_AT));

        Optional<AdminSession> found = store.find(SESSION_HASH);

        assertTrue(found.isPresent());
        assertEquals(SESSION_HASH, found.orElseThrow().tokenHash());
        assertEquals(USER_ID, found.orElseThrow().state().userId());
        assertEquals(CSRF_HASH, found.orElseThrow().state().csrfTokenHash());
        assertEquals(EXPIRES_AT, found.orElseThrow().state().expiresAt());
    }

    @Test
    void missingOrRevokedSessionReturnsEmpty() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(false);

        assertTrue(store.find(SESSION_HASH).isEmpty());
    }

    @Test
    void revokeUsesTheHashedTokenAndIsIdempotent() throws Exception {
        when(statement.executeUpdate()).thenReturn(1, 0);

        store.revoke(SESSION_HASH);
        store.revoke(SESSION_HASH);

        verify(statement, org.mockito.Mockito.times(2))
                .setString(1, SESSION_HASH);
        verify(statement, org.mockito.Mockito.times(2)).executeUpdate();
    }

    @Test
    void rejectsRawOrMalformedTokenMaterialBeforeQuerying() {
        AdminAuthenticationException raw = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find("raw-session-token")
        );
        assertEquals("INTERNAL_CONFIGURATION", raw.code());

        AdminAuthenticationException csrf = assertThrows(
                AdminAuthenticationException.class,
                () -> store.create(
                        SESSION_HASH,
                        new AdminSessionState(
                                USER_ID,
                                "raw-csrf-token",
                                EXPIRES_AT
                        )
                )
        );
        assertEquals("INTERNAL_CONFIGURATION", csrf.code());
    }

    @Test
    void databaseFailureIsRetryableStoreUnavailable() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("down"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(SESSION_HASH)
        );

        assertEquals("SESSION_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void createRejectsUnexpectedAffectedRowCount() throws Exception {
        when(statement.executeUpdate()).thenReturn(0);

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.create(
                        SESSION_HASH,
                        new AdminSessionState(USER_ID, CSRF_HASH, EXPIRES_AT)
                )
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void createDatabaseFailureIsRetryable() throws Exception {
        when(statement.executeUpdate()).thenThrow(new SQLException("down"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.create(
                        SESSION_HASH,
                        new AdminSessionState(USER_ID, CSRF_HASH, EXPIRES_AT)
                )
        );

        assertEquals("SESSION_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void multipleSessionRowsFailClosed() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, true);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(resultSet.getString("csrf_token_hash")).thenReturn(CSRF_HASH);
        when(resultSet.getTimestamp("expires_at"))
                .thenReturn(Timestamp.from(EXPIRES_AT));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(SESSION_HASH)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void malformedSessionMetadataFailsClosed() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(resultSet.getString("csrf_token_hash"))
                .thenReturn("not-a-hash");
        when(resultSet.getTimestamp("expires_at"))
                .thenReturn(Timestamp.from(EXPIRES_AT));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(SESSION_HASH)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void missingSessionUserFailsClosed() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getString("csrf_token_hash")).thenReturn(CSRF_HASH);
        when(resultSet.getTimestamp("expires_at"))
                .thenReturn(Timestamp.from(EXPIRES_AT));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(SESSION_HASH)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void missingSessionExpiryFailsClosed() throws Exception {
        ResultSet resultSet = mock(ResultSet.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(USER_ID);
        when(resultSet.getString("csrf_token_hash")).thenReturn(CSRF_HASH);

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(SESSION_HASH)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void revokeDatabaseFailureIsRetryable() throws Exception {
        when(statement.executeUpdate()).thenThrow(new SQLException("down"));

        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                () -> store.revoke(SESSION_HASH)
        );

        assertEquals("SESSION_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void nullTokenHashAndSessionStateAreRejected() {
        AdminAuthenticationException nullToken = assertThrows(
                AdminAuthenticationException.class,
                () -> store.find(null)
        );
        assertEquals("INTERNAL_CONFIGURATION", nullToken.code());

        assertThrows(
                NullPointerException.class,
                () -> store.create(SESSION_HASH, null)
        );
    }
}
