package com.apiproject.app.security;

import com.apiproject.gateway.security.ApiTarget;
import com.apiproject.gateway.security.ApiTargetResolutionException;
import com.apiproject.gateway.security.AuthorizedApi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcApiTargetResolverTest {

    private static final AuthorizedApi AUTHORIZED_API = new AuthorizedApi(
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "PLATFORM_PUBLIC",
            Map.of("itemId", "item-123")
    );

    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement statement;
    private ResultSet resultSet;
    private JdbcApiTargetResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        resultSet = mock(ResultSet.class);
        resolver = new JdbcApiTargetResolver(dataSource);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true, false);
    }

    @Test
    void resolvesPublishedUpstreamTarget() throws Exception {
        when(resultSet.getString("upstream_method")).thenReturn("PATCH");
        when(resultSet.getString("upstream_path_template"))
                .thenReturn("/items/{itemId}");
        when(resultSet.getString("base_url"))
                .thenReturn("https://upstream.example.test/v1");
        when(resultSet.getInt("timeout_ms")).thenReturn(1_500);

        ApiTarget target = resolver.resolve(AUTHORIZED_API);

        assertEquals("PATCH", target.method());
        assertEquals("/items/{itemId}", target.pathTemplate());
        assertEquals(
                java.net.URI.create("https://upstream.example.test/v1"),
                target.baseUri()
        );
        assertEquals(Duration.ofMillis(1_500), target.timeout());
    }

    @Test
    void missingTargetFailsAsUpstreamConfiguration() throws Exception {
        when(resultSet.next()).thenReturn(false);

        ApiTargetResolutionException exception = assertThrows(
                ApiTargetResolutionException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );

        assertEquals("UPSTREAM_CONFIGURATION_ERROR", exception.code());
        assertFalse(exception.retryable());
    }

    @Test
    void unsafeOrIncompleteTargetFailsClosed() throws Exception {
        when(resultSet.getString("upstream_method")).thenReturn("PATCH");
        when(resultSet.getString("upstream_path_template"))
                .thenReturn("/items/{itemId}");
        when(resultSet.getString("base_url"))
                .thenReturn("http://127.0.0.1/internal");
        when(resultSet.getInt("timeout_ms")).thenReturn(1_500);

        assertThrows(
                ApiTargetResolutionException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );

        when(resultSet.getString("base_url"))
                .thenReturn("https://user@upstream.example.test/v1");
        assertThrows(
                ApiTargetResolutionException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );
    }

    @Test
    void databaseFailureFailsClosedWithoutLeakingDetails() throws Exception {
        when(dataSource.getConnection())
                .thenThrow(new SQLException("database secret"));

        ApiTargetResolutionException exception = assertThrows(
                ApiTargetResolutionException.class,
                () -> resolver.resolve(AUTHORIZED_API)
        );

        assertEquals("UPSTREAM_CONFIGURATION_ERROR", exception.code());
        assertFalse(exception.getMessage().contains("database secret"));
    }
}
