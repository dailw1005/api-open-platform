package com.apiproject.app.security;

import com.apiproject.gateway.security.ApiAuthorizationException;
import com.apiproject.gateway.security.ApiAuthorizationGate;
import com.apiproject.gateway.security.AuthorizedApi;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;

public final class JdbcApiAuthorizationGate implements ApiAuthorizationGate {

    private static final String AUTHORIZATION_SQL = """
            SELECT decision, api_id, api_version_id, tenant_id, visibility
            FROM auth_authorize_public_api(?, ?, ?)
            """;

    private final DataSource dataSource;

    public JdbcApiAuthorizationGate(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public AuthorizedApi authorize(String appKey, String method, String path) {
        Objects.requireNonNull(appKey, "appKey");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     AUTHORIZATION_SQL
             )) {
            statement.setString(1, appKey);
            statement.setString(2, method);
            statement.setString(3, path);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw internalConfiguration(
                            "Authorization lookup returned no decision",
                            null
                    );
                }
                String decision = resultSet.getString("decision");
                if (!"ALLOWED".equals(decision)) {
                    throw decisionFailure(decision);
                }

                UUID apiId = resultSet.getObject("api_id", UUID.class);
                UUID apiVersionId = resultSet.getObject(
                        "api_version_id",
                        UUID.class
                );
                UUID tenantId = resultSet.getObject("tenant_id", UUID.class);
                String visibility = resultSet.getString("visibility");
                if (apiId == null
                        || apiVersionId == null
                        || tenantId == null
                        || visibility == null) {
                    throw internalConfiguration(
                            "Authorization lookup returned invalid metadata",
                            null
                    );
                }
                if (resultSet.next()) {
                    throw internalConfiguration(
                            "Authorization lookup returned multiple decisions",
                            null
                    );
                }
                return new AuthorizedApi(
                        apiId,
                        apiVersionId,
                        tenantId,
                        visibility
                );
            }
        } catch (SQLException exception) {
            throw new ApiAuthorizationException(
                    "AUTHORIZATION_STORE_UNAVAILABLE",
                    true,
                    "Authorization store is unavailable",
                    exception
            );
        }
    }

    private ApiAuthorizationException decisionFailure(String decision) {
        if ("API_NOT_FOUND".equals(decision)) {
            return new ApiAuthorizationException(
                    "API_NOT_FOUND",
                    false,
                    "API was not found",
                    null
            );
        }
        if ("API_NOT_GRANTED".equals(decision)) {
            return new ApiAuthorizationException(
                    "API_NOT_GRANTED",
                    false,
                    "Application is not granted this API",
                    null
            );
        }
        if ("INVALID_CREDENTIAL".equals(decision)) {
            return new ApiAuthorizationException(
                    "INVALID_CREDENTIAL",
                    false,
                    "Credential is invalid",
                    null
            );
        }
        return internalConfiguration(
                "Authorization lookup returned an unknown decision",
                null
        );
    }

    private ApiAuthorizationException internalConfiguration(
            String message,
            Throwable cause
    ) {
        return new ApiAuthorizationException(
                "INTERNAL_CONFIGURATION",
                false,
                message,
                cause
        );
    }
}
