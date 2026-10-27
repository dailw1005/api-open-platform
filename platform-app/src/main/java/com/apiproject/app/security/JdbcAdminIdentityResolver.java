package com.apiproject.app.security;

import com.apiproject.control.iam.AdminAuthenticationException;
import com.apiproject.control.iam.AdminIdentity;
import com.apiproject.control.iam.AdminIdentityResolver;
import com.apiproject.control.iam.AdminLoginIdentity;
import com.apiproject.control.iam.SessionRoleBinding;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class JdbcAdminIdentityResolver implements AdminIdentityResolver {

    private static final String USER_BY_EMAIL_SQL = """
            SELECT id, email, display_name, password_hash, mfa_enabled
            FROM iam_user
            WHERE email = ? AND status = 'ACTIVE'
            """;
    private static final String USER_BY_ID_SQL = """
            SELECT id, email, display_name, password_hash, mfa_enabled
            FROM iam_user
            WHERE id = ? AND status = 'ACTIVE'
            """;
    private static final String ROLES_SQL = """
            SELECT id, user_id, tenant_id, role_code, scope_type
            FROM iam_role_binding
            WHERE user_id = ?
            ORDER BY scope_type DESC, id
            """;

    private final DataSource dataSource;

    public JdbcAdminIdentityResolver(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<AdminLoginIdentity> findByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        try (Connection connection = dataSource.getConnection()) {
            Optional<UserRecord> user = findUser(
                    connection,
                    USER_BY_EMAIL_SQL,
                    email
            );
            if (user.isEmpty()) {
                return Optional.empty();
            }
            List<SessionRoleBinding> roles = findRoles(
                    connection,
                    user.orElseThrow().id()
            );
            return Optional.of(new AdminLoginIdentity(
                    toAdminIdentity(user.orElseThrow(), roles),
                    user.orElseThrow().passwordHash(),
                    user.orElseThrow().mfaEnabled()
            ));
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    @Override
    public Optional<AdminIdentity> findByUserId(UUID userId) {
        Objects.requireNonNull(userId, "userId");
        try (Connection connection = dataSource.getConnection()) {
            Optional<UserRecord> user = findUser(
                    connection,
                    USER_BY_ID_SQL,
                    userId
            );
            if (user.isEmpty()) {
                return Optional.empty();
            }
            List<SessionRoleBinding> roles = findRoles(
                    connection,
                    user.orElseThrow().id()
            );
            return Optional.of(toAdminIdentity(user.orElseThrow(), roles));
        } catch (SQLException exception) {
            throw storeUnavailable(exception);
        }
    }

    private Optional<UserRecord> findUser(
            Connection connection,
            String sql,
            Object identifier
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, identifier);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                UserRecord user = readUser(resultSet);
                if (resultSet.next()) {
                    throw internalConfiguration(
                            "Identity lookup returned multiple users"
                    );
                }
                return Optional.of(user);
            }
        }
    }

    private List<SessionRoleBinding> findRoles(
            Connection connection,
            UUID userId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                ROLES_SQL
        )) {
            statement.setObject(1, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                List<SessionRoleBinding> roles = new ArrayList<>();
                while (resultSet.next()) {
                    roles.add(readRole(resultSet, userId));
                }
                return List.copyOf(roles);
            }
        }
    }

    private UserRecord readUser(ResultSet resultSet) throws SQLException {
        UUID id = resultSet.getObject("id", UUID.class);
        String email = resultSet.getString("email");
        String displayName = resultSet.getString("display_name");
        String passwordHash = resultSet.getString("password_hash");
        if (id == null
                || email == null
                || email.isBlank()
                || displayName == null
                || displayName.isBlank()
                || displayName.length() > 100
                || passwordHash == null
                || passwordHash.isBlank()) {
            throw internalConfiguration(
                    "Identity lookup returned malformed user metadata"
            );
        }
        return new UserRecord(
                id,
                email,
                displayName,
                passwordHash,
                resultSet.getBoolean("mfa_enabled")
        );
    }

    private SessionRoleBinding readRole(ResultSet resultSet, UUID userId) {
        try {
            UUID roleUserId = resultSet.getObject("user_id", UUID.class);
            if (!userId.equals(roleUserId)) {
                throw internalConfiguration(
                        "Identity lookup returned a foreign role binding"
                );
            }
            return new SessionRoleBinding(
                    resultSet.getObject("id", UUID.class),
                    roleUserId,
                    resultSet.getObject("tenant_id", UUID.class),
                    resultSet.getString("role_code"),
                    resultSet.getString("scope_type")
            );
        } catch (SQLException exception) {
            throw internalConfiguration(
                    "Identity role lookup failed",
                    exception
            );
        } catch (IllegalArgumentException exception) {
            throw internalConfiguration(
                    "Identity role lookup returned malformed metadata",
                    exception
            );
        }
    }

    private AdminIdentity toAdminIdentity(
            UserRecord user,
            List<SessionRoleBinding> roles
    ) {
        return new AdminIdentity(
                user.id(),
                user.email(),
                user.displayName(),
                roles
        );
    }

    private AdminAuthenticationException storeUnavailable(SQLException cause) {
        return new AdminAuthenticationException(
                "IDENTITY_STORE_UNAVAILABLE",
                true,
                "Identity store is unavailable",
                cause
        );
    }

    private AdminAuthenticationException internalConfiguration(String message) {
        return internalConfiguration(message, null);
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

    private record UserRecord(
            UUID id,
            String email,
            String displayName,
            String passwordHash,
            boolean mfaEnabled
    ) {
    }
}
