package com.apiproject.app.security;

import com.apiproject.gateway.security.ActiveCredentialResolver;
import com.apiproject.gateway.security.CredentialResolutionException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class JdbcActiveCredentialResolver implements ActiveCredentialResolver {

    private static final int MINIMUM_SECRET_BYTES = 32;
    private static final String LOOKUP_SQL = """
            SELECT credential_id, tenant_id, app_id, kms_key_id,
                   secret_ciphertext, app_auth_epoch, credential_auth_epoch
            FROM auth_resolve_active_credential(?)
            """;

    private final DataSource dataSource;
    private final CredentialSecretDecryptor decryptor;

    public JdbcActiveCredentialResolver(
            DataSource dataSource,
            CredentialSecretDecryptor decryptor
    ) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.decryptor = Objects.requireNonNull(decryptor, "decryptor");
    }

    @Override
    public Optional<byte[]> resolveActiveSecret(String appKey) {
        Objects.requireNonNull(appKey, "appKey");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(LOOKUP_SQL)) {
            statement.setString(1, appKey);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }

                CredentialRow row = readRow(resultSet, appKey);
                if (resultSet.next()) {
                    throw internalConfiguration(
                            "Credential lookup returned multiple rows",
                            null
                    );
                }

                return Optional.of(decrypt(row));
            }
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    private CredentialRow readRow(ResultSet resultSet, String appKey)
            throws SQLException {
        UUID credentialId = resultSet.getObject("credential_id", UUID.class);
        UUID tenantId = resultSet.getObject("tenant_id", UUID.class);
        UUID appId = resultSet.getObject("app_id", UUID.class);
        String kmsKeyId = resultSet.getString("kms_key_id");
        byte[] ciphertext = resultSet.getBytes("secret_ciphertext");
        long appAuthEpoch = resultSet.getLong("app_auth_epoch");
        long credentialAuthEpoch = resultSet.getLong("credential_auth_epoch");

        if (credentialId == null
                || tenantId == null
                || appId == null
                || kmsKeyId == null
                || ciphertext == null
                || appAuthEpoch <= 0
                || credentialAuthEpoch <= 0) {
            throw internalConfiguration(
                    "Credential lookup returned invalid metadata",
                    null
            );
        }
        return new CredentialRow(
                credentialId,
                tenantId,
                appId,
                appKey,
                kmsKeyId,
                ciphertext
        );
    }

    private byte[] decrypt(CredentialRow row) {
        byte[] plaintext;
        try {
            plaintext = decryptor.decrypt(
                    new CredentialEncryptionContext(
                            row.tenantId(),
                            row.appId(),
                            row.credentialId(),
                            row.appKey(),
                            row.kmsKeyId()
                    ),
                    row.ciphertext().clone()
            );
        } catch (CredentialDecryptionException exception) {
            if (exception.retryable()) {
                throw storeUnavailable(exception);
            }
            throw internalConfiguration("Credential decryption failed", exception);
        } catch (RuntimeException exception) {
            throw internalConfiguration("Credential decryption failed", exception);
        }

        if (plaintext == null || plaintext.length < MINIMUM_SECRET_BYTES) {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
            throw internalConfiguration("Credential plaintext is invalid", null);
        }
        return plaintext;
    }

    private CredentialResolutionException storeUnavailable(Throwable cause) {
        return new CredentialResolutionException(
                "CREDENTIAL_STORE_UNAVAILABLE",
                true,
                "Credential store is unavailable",
                cause
        );
    }

    private CredentialResolutionException internalConfiguration(
            String message,
            Throwable cause
    ) {
        return new CredentialResolutionException(
                "INTERNAL_CONFIGURATION",
                false,
                message,
                cause
        );
    }

    private record CredentialRow(
            UUID credentialId,
            UUID tenantId,
            UUID appId,
            String appKey,
            String kmsKeyId,
            byte[] ciphertext
    ) {
    }
}
