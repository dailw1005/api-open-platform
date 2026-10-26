package com.apiproject.app.security;

import com.apiproject.gateway.security.CredentialResolutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcActiveCredentialResolverTest {

    private static final String APP_KEY = "ak_resolver_1234567890abcdef";
    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final UUID APP_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();
    private static final byte[] CIPHERTEXT = new byte[]{1, 2, 3, 4};
    private static final byte[] SECRET = new byte[32];

    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement statement;
    private ResultSet resultSet;
    private CredentialSecretDecryptor decryptor;
    private JdbcActiveCredentialResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        resultSet = mock(ResultSet.class);
        decryptor = mock(CredentialSecretDecryptor.class);
        resolver = new JdbcActiveCredentialResolver(dataSource, decryptor);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
    }

    @Test
    void resolvesActiveCredentialAndReturnsDecryptedSecret() throws Exception {
        stubActiveRow();
        when(decryptor.decrypt(any(CredentialEncryptionContext.class), any(byte[].class)))
                .thenReturn(SECRET.clone());

        Optional<byte[]> resolved = resolver.resolveActiveSecret(APP_KEY);

        assertTrue(resolved.isPresent());
        assertArrayEquals(SECRET, resolved.orElseThrow());
    }

    @Test
    void unknownCredentialReturnsEmpty() throws Exception {
        when(resultSet.next()).thenReturn(false);

        Optional<byte[]> resolved = resolver.resolveActiveSecret(APP_KEY);

        assertFalse(resolved.isPresent());
    }

    @Test
    void databaseFailureIsTypedAsRetryableStoreUnavailable() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("database down"));

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                () -> resolver.resolveActiveSecret(APP_KEY)
        );

        assertEquals("CREDENTIAL_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void retryableDecryptionFailureMapsToStoreUnavailable() throws Exception {
        stubActiveRow();
        when(decryptor.decrypt(any(CredentialEncryptionContext.class), any(byte[].class)))
                .thenThrow(new CredentialDecryptionException(
                        true,
                        "kms unavailable",
                        null
                ));

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                () -> resolver.resolveActiveSecret(APP_KEY)
        );

        assertEquals("CREDENTIAL_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void nonRetryableDecryptionFailureMapsToInternalConfiguration() throws Exception {
        stubActiveRow();
        when(decryptor.decrypt(any(CredentialEncryptionContext.class), any(byte[].class)))
                .thenThrow(new CredentialDecryptionException(
                        false,
                        "ciphertext is invalid",
                        null
                ));

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                () -> resolver.resolveActiveSecret(APP_KEY)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertFalse(exception.retryable());
    }

    @Test
    void invalidPlaintextLengthIsWipedAndFailsClosed() throws Exception {
        stubActiveRow();
        byte[] invalidSecret = new byte[31];
        when(decryptor.decrypt(any(CredentialEncryptionContext.class), any(byte[].class)))
                .thenReturn(invalidSecret);

        CredentialResolutionException exception = assertThrows(
                CredentialResolutionException.class,
                () -> resolver.resolveActiveSecret(APP_KEY)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertArrayEquals(new byte[31], invalidSecret);
    }

    private void stubActiveRow() throws SQLException {
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getObject("credential_id", UUID.class))
                .thenReturn(CREDENTIAL_ID);
        when(resultSet.getObject("tenant_id", UUID.class)).thenReturn(TENANT_ID);
        when(resultSet.getObject("app_id", UUID.class)).thenReturn(APP_ID);
        when(resultSet.getString("kms_key_id")).thenReturn("test-kms-key");
        when(resultSet.getBytes("secret_ciphertext")).thenReturn(CIPHERTEXT.clone());
        when(resultSet.getLong("app_auth_epoch")).thenReturn(2L);
        when(resultSet.getLong("credential_auth_epoch")).thenReturn(3L);
    }
}
