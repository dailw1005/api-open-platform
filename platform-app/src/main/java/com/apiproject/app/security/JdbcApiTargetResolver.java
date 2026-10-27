package com.apiproject.app.security;

import com.apiproject.gateway.security.ApiTarget;
import com.apiproject.gateway.security.ApiTargetResolutionException;
import com.apiproject.gateway.security.ApiTargetResolver;
import com.apiproject.gateway.security.AuthorizedApi;

import javax.sql.DataSource;
import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;

public final class JdbcApiTargetResolver implements ApiTargetResolver {

    private static final String TARGET_SQL = """
            SELECT
                upstream_method,
                upstream_path_template,
                base_url,
                timeout_ms
            FROM auth_resolve_api_target(?, ?)
            """;

    private final DataSource dataSource;

    public JdbcApiTargetResolver(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public ApiTarget resolve(AuthorizedApi authorizedApi) {
        Objects.requireNonNull(authorizedApi, "authorizedApi");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     TARGET_SQL
             )) {
            statement.setObject(1, authorizedApi.apiId());
            statement.setObject(2, authorizedApi.apiVersionId());
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw configurationError(
                            "Published upstream target was not found",
                            null
                    );
                }
                ApiTarget target = new ApiTarget(
                        URI.create(resultSet.getString("base_url")),
                        resultSet.getString("upstream_method"),
                        resultSet.getString("upstream_path_template"),
                        Duration.ofMillis(resultSet.getInt("timeout_ms"))
                );
                if (resultSet.next()) {
                    throw configurationError(
                            "Published upstream target is ambiguous",
                            null
                    );
                }
                return target;
            }
        } catch (ApiTargetResolutionException exception) {
            throw exception;
        } catch (SQLException exception) {
            throw new ApiTargetResolutionException(
                    "TARGET_STORE_UNAVAILABLE",
                    true,
                    "Published upstream target store is unavailable",
                    exception
            );
        } catch (IllegalArgumentException exception) {
            throw configurationError(
                    "Published upstream target is invalid",
                    exception
            );
        }
    }

    private ApiTargetResolutionException configurationError(
            String message,
            Throwable cause
    ) {
        return new ApiTargetResolutionException(
                "UPSTREAM_CONFIGURATION_ERROR",
                false,
                message,
                cause
        );
    }
}
