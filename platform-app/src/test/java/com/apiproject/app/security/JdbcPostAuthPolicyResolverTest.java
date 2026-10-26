package com.apiproject.app.security;

import com.apiproject.app.PostAuthLimitProperties;
import com.apiproject.gateway.security.AuthorizedApi;
import com.apiproject.gateway.security.PostAuthPolicy;
import com.apiproject.gateway.security.PostAuthRateLimitException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcPostAuthPolicyResolverTest {

    private static final AuthorizedApi AUTHORIZED_API = new AuthorizedApi(
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "PLATFORM_PUBLIC"
    );

    private PostAuthLimitProperties properties;
    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement statement;
    private ResultSet resultSet;
    private JdbcPostAuthPolicyResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        properties = new PostAuthLimitProperties(
                new PostAuthLimitProperties.TokenBucket(
                        100,
                        Duration.ofMinutes(1),
                        20
                ),
                new PostAuthLimitProperties.TokenBucket(
                        50,
                        Duration.ofMinutes(1),
                        10
                ),
                new PostAuthLimitProperties.Quota(10_000, 200_000),
                new PostAuthLimitProperties.Quota(5_000, 100_000)
        );
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        resultSet = mock(ResultSet.class);
        resolver = new JdbcPostAuthPolicyResolver(dataSource, properties);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
    }

    @Test
    void returnsConfiguredDefaultsWhenNoPolicyOverridesExist() throws Exception {
        PostAuthPolicy policy = resolver.resolve(AUTHORIZED_API);

        assertEquals(properties.defaultPolicy(), policy);
    }

    @Test
    void returnsCompleteApplicationAndApiOverrides() throws Exception {
        when(resultSet.getObject("app_rate_requests", Long.class))
                .thenReturn(30L);
        when(resultSet.getObject("app_rate_window_seconds", Integer.class))
                .thenReturn(60);
        when(resultSet.getObject("app_rate_burst", Integer.class))
                .thenReturn(6);
        when(resultSet.getObject("api_rate_requests", Long.class))
                .thenReturn(20L);
        when(resultSet.getObject("api_rate_window_seconds", Integer.class))
                .thenReturn(60);
        when(resultSet.getObject("api_rate_burst", Integer.class))
                .thenReturn(4);
        when(resultSet.getObject("app_daily_quota", Long.class))
                .thenReturn(1_000L);
        when(resultSet.getObject("app_monthly_quota", Long.class))
                .thenReturn(10_000L);
        when(resultSet.getObject("api_daily_quota", Long.class))
                .thenReturn(500L);
        when(resultSet.getObject("api_monthly_quota", Long.class))
                .thenReturn(5_000L);

        PostAuthPolicy policy = resolver.resolve(AUTHORIZED_API);

        assertEquals(30, policy.applicationTokenBucket().requests());
        assertEquals(6, policy.applicationTokenBucket().burst());
        assertEquals(20, policy.apiTokenBucket().requests());
        assertEquals(4, policy.apiTokenBucket().burst());
        assertEquals(1_000, policy.applicationQuota().dailyLimit());
        assertEquals(10_000, policy.applicationQuota().monthlyLimit());
        assertEquals(500, policy.apiQuota().dailyLimit());
        assertEquals(5_000, policy.apiQuota().monthlyLimit());
    }

    @Test
    void partialPolicyGroupFailsAsInternalConfiguration() throws Exception {
        when(resultSet.getObject("app_rate_requests", Long.class))
                .thenReturn(30L);

        PostAuthRateLimitException exception = assertThrows(
                PostAuthRateLimitException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
        assertTrue(!exception.retryable());
    }

    @Test
    void databaseFailureIsRetryableRateLimitUnavailable() throws Exception {
        when(dataSource.getConnection())
                .thenThrow(new SQLException("database down"));

        PostAuthRateLimitException exception = assertThrows(
                PostAuthRateLimitException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );

        assertEquals("RATE_LIMIT_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
        assertTrue(!exception.getMessage().contains("database down"));
    }

    @Test
    void missingOrMultipleRowsFailClosed() throws Exception {
        when(resultSet.next()).thenReturn(false);

        PostAuthRateLimitException missing = assertThrows(
                PostAuthRateLimitException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );
        assertEquals("INTERNAL_CONFIGURATION", missing.code());

        when(resultSet.next()).thenReturn(true, true);
        PostAuthRateLimitException multiple = assertThrows(
                PostAuthRateLimitException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );
        assertEquals("INTERNAL_CONFIGURATION", multiple.code());
    }
}
