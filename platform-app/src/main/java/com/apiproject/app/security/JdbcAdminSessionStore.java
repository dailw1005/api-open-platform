package com.apiproject.app.security;

import com.apiproject.control.iam.AdminAuthenticationException;
import com.apiproject.control.iam.AdminSession;
import com.apiproject.control.iam.AdminSessionState;
import com.apiproject.control.iam.AdminSessionStore;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public final class JdbcAdminSessionStore implements AdminSessionStore {

    private static final Pattern SHA256_HEX =
            Pattern.compile("^[0-9a-f]{64}$");
    private static final String CREATE_SQL = """
            INSERT INTO iam_session (
                token_hash, user_id, csrf_token_hash, expires_at
            ) VALUES (?, ?, ?, ?)
            """;
    private static final String FIND_SQL = """
            SELECT user_id, csrf_token_hash, expires_at
            FROM iam_session
            WHERE token_hash = ? AND revoked_at IS NULL
            """;
    private static final String REVOKE_SQL = """
            UPDATE iam_session
            SET revoked_at = now()
            WHERE token_hash = ? AND revoked_at IS NULL
            """;

    private final DataSource dataSource;

    public JdbcAdminSessionStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public void create(String tokenHash, AdminSessionState state) {
        requireHash(tokenHash, "tokenHash");
        Objects.requireNonNull(state, "state");
        requireHash(state.csrfTokenHash(), "csrfTokenHash");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     CREATE_SQL
             )) {
            statement.setString(1, tokenHash);
            statement.setObject(2, state.userId());
            statement.setString(3, state.csrfTokenHash());
            statement.setTimestamp(4, Timestamp.from(state.expiresAt()));
            if (statement.executeUpdate() != 1) {
                throw internalConfiguration(
                        "Session insert did not create exactly one row",
                        null
                );
            }
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    @Override
    public Optional<AdminSession> find(String tokenHash) {
        requireHash(tokenHash, "tokenHash");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     FIND_SQL
             )) {
            statement.setString(1, tokenHash);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                AdminSession session = new AdminSession(
                        tokenHash,
                        readState(resultSet)
                );
                if (resultSet.next()) {
                    throw internalConfiguration(
                            "Session lookup returned multiple rows",
                            null
                    );
                }
                return Optional.of(session);
            }
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    @Override
    public void revoke(String tokenHash) {
        requireHash(tokenHash, "tokenHash");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     REVOKE_SQL
             )) {
            statement.setString(1, tokenHash);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    private AdminSessionState readState(ResultSet resultSet) throws SQLException {
        UUID userId = resultSet.getObject("user_id", UUID.class);
        String csrfHash = resultSet.getString("csrf_token_hash");
        Timestamp expiresAt = resultSet.getTimestamp("expires_at");
        if (userId == null
                || csrfHash == null
                || !SHA256_HEX.matcher(csrfHash).matches()
                || expiresAt == null) {
            throw internalConfiguration(
                    "Session lookup returned malformed metadata",
                    null
            );
        }
        return new AdminSessionState(
                userId,
                csrfHash,
                expiresAt.toInstant()
        );
    }

    private void requireHash(String value, String field) {
        if (value == null || !SHA256_HEX.matcher(value).matches()) {
            throw internalConfiguration(
                    field + " must be lowercase SHA-256 hex",
                    null
            );
        }
    }

    private AdminAuthenticationException storeUnavailable(SQLException cause) {
        return new AdminAuthenticationException(
                "SESSION_STORE_UNAVAILABLE",
                true,
                "Session store is unavailable",
                cause
        );
    }

    private AdminAuthenticationException internalConfiguration(
            String message,
            Throwable cause
    ) {
        return new AdminAuthenticationException(
                "INTERNAL_CONFIGURATION",
                false,
                message,
                cause
        );
    }
}
