package com.apiproject.app.security;

import com.apiproject.app.PostAuthLimitProperties;
import com.apiproject.gateway.security.AuthorizedApi;
import com.apiproject.gateway.security.PostAuthPolicy;
import com.apiproject.gateway.security.PostAuthPolicyResolver;
import com.apiproject.gateway.security.PostAuthRateLimitException;
import com.apiproject.gateway.security.QuotaPolicy;
import com.apiproject.gateway.security.TokenBucketPolicy;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;

public final class JdbcPostAuthPolicyResolver
        implements PostAuthPolicyResolver {

    private static final String POLICY_SQL = """
            SELECT
                app_rate_requests,
                app_rate_window_seconds,
                app_rate_burst,
                api_rate_requests,
                api_rate_window_seconds,
                api_rate_burst,
                app_daily_quota,
                app_monthly_quota,
                api_daily_quota,
                api_monthly_quota
            FROM auth_resolve_post_auth_policies(?, ?)
            """;

    private final DataSource dataSource;
    private final PostAuthPolicy defaultPolicy;

    public JdbcPostAuthPolicyResolver(
            DataSource dataSource,
            PostAuthLimitProperties properties
    ) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.defaultPolicy = Objects.requireNonNull(
                properties,
                "properties"
        ).defaultPolicy();
    }

    @Override
    public PostAuthPolicy resolve(AuthorizedApi authorizedApi) {
        Objects.requireNonNull(authorizedApi, "authorizedApi");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     POLICY_SQL
             )) {
            statement.setObject(1, authorizedApi.appId());
            statement.setObject(2, authorizedApi.apiId());
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw configurationError(
                            "Post-auth policy lookup returned no row",
                            null
                    );
                }
                PostAuthPolicy policy = readPolicy(resultSet);
                if (resultSet.next()) {
                    throw configurationError(
                            "Post-auth policy lookup returned multiple rows",
                            null
                    );
                }
                return policy;
            }
        } catch (SQLException exception) {
            throw new PostAuthRateLimitException(
                    "RATE_LIMIT_UNAVAILABLE",
                    true,
                    "Post-auth policy store is unavailable",
                    exception
            );
        } catch (PostAuthRateLimitException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw configurationError(
                    "Post-auth policy lookup returned invalid values",
                    exception
            );
        }
    }

    private PostAuthPolicy readPolicy(ResultSet resultSet) throws SQLException {
        Long appRequests = resultSet.getObject(
                "app_rate_requests",
                Long.class
        );
        Integer appWindow = resultSet.getObject(
                "app_rate_window_seconds",
                Integer.class
        );
        Integer appBurst = resultSet.getObject("app_rate_burst", Integer.class);
        Long apiRequests = resultSet.getObject(
                "api_rate_requests",
                Long.class
        );
        Integer apiWindow = resultSet.getObject(
                "api_rate_window_seconds",
                Integer.class
        );
        Integer apiBurst = resultSet.getObject("api_rate_burst", Integer.class);
        Long appDaily = resultSet.getObject("app_daily_quota", Long.class);
        Long appMonthly = resultSet.getObject("app_monthly_quota", Long.class);
        Long apiDaily = resultSet.getObject("api_daily_quota", Long.class);
        Long apiMonthly = resultSet.getObject("api_monthly_quota", Long.class);

        return new PostAuthPolicy(
                tokenBucket(
                        appRequests,
                        appWindow,
                        appBurst,
                        defaultPolicy.applicationTokenBucket()
                ),
                tokenBucket(
                        apiRequests,
                        apiWindow,
                        apiBurst,
                        defaultPolicy.apiTokenBucket()
                ),
                quota(
                        appDaily,
                        appMonthly,
                        defaultPolicy.applicationQuota()
                ),
                quota(apiDaily, apiMonthly, defaultPolicy.apiQuota())
        );
    }

    private TokenBucketPolicy tokenBucket(
            Long requests,
            Integer windowSeconds,
            Integer burst,
            TokenBucketPolicy fallback
    ) {
        if (requests == null && windowSeconds == null && burst == null) {
            return fallback;
        }
        if (requests == null || windowSeconds == null || burst == null) {
            throw configurationError(
                    "Post-auth token bucket policy is incomplete",
                    null
            );
        }
        return new TokenBucketPolicy(
                requests,
                Duration.ofSeconds(windowSeconds),
                burst
        );
    }

    private QuotaPolicy quota(
            Long daily,
            Long monthly,
            QuotaPolicy fallback
    ) {
        return new QuotaPolicy(
                daily == null ? fallback.dailyLimit() : daily,
                monthly == null ? fallback.monthlyLimit() : monthly
        );
    }

    private PostAuthRateLimitException configurationError(
            String message,
            Throwable cause
    ) {
        return new PostAuthRateLimitException(
                "INTERNAL_CONFIGURATION",
                false,
                message,
                cause
        );
    }
}
