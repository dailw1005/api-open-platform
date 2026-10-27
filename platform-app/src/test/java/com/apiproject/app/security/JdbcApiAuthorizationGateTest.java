package com.apiproject.app.security;

import com.apiproject.gateway.security.ApiAuthorizationException;
import com.apiproject.gateway.security.AuthorizedApi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcApiAuthorizationGateTest {

    private static final String APP_KEY = "ak_authorization_gate_123456";
    private static final UUID APP_ID = UUID.randomUUID();
    private static final UUID API_ID = UUID.randomUUID();
    private static final UUID VERSION_ID = UUID.randomUUID();
    private static final UUID TENANT_ID = UUID.randomUUID();

    private DataSource dataSource;
    private Connection connection;
    private PreparedStatement statement;
    private ResultSet resultSet;
    private JdbcApiAuthorizationGate gate;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        resultSet = mock(ResultSet.class);
        gate = new JdbcApiAuthorizationGate(dataSource);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
    }

    @Test
    void allowedDecisionReturnsAuthorizedApi() throws Exception {
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getString("decision")).thenReturn("ALLOWED");
        when(resultSet.getObject("app_id", UUID.class)).thenReturn(APP_ID);
        when(resultSet.getObject("api_id", UUID.class)).thenReturn(API_ID);
        when(resultSet.getObject("api_version_id", UUID.class)).thenReturn(VERSION_ID);
        when(resultSet.getObject("tenant_id", UUID.class)).thenReturn(TENANT_ID);
        when(resultSet.getString("visibility")).thenReturn("PLATFORM_PUBLIC");
        when(resultSet.getString("route_params"))
                .thenReturn("{\"orderId\":\"order-123\"}");

        AuthorizedApi api = gate.authorize(APP_KEY, "GET", "/open/v1/orders");

        assertEquals(APP_ID, api.appId());
        assertEquals(API_ID, api.apiId());
        assertEquals(VERSION_ID, api.apiVersionId());
        assertEquals(TENANT_ID, api.tenantId());
        assertEquals("PLATFORM_PUBLIC", api.visibility());
        assertEquals(Map.of("orderId", "order-123"), api.routeParameters());
    }

    @Test
    void decisionFailuresMapToStableCodes() throws Exception {
        assertDecision("API_NOT_FOUND", false);
        assertDecision("API_NOT_GRANTED", false);
        assertDecision("INVALID_CREDENTIAL", false);
        assertDecision("UNKNOWN", false);
    }

    @Test
    void missingDecisionFailsClosed() throws Exception {
        when(resultSet.next()).thenReturn(false);

        ApiAuthorizationException exception = assertThrows(
                ApiAuthorizationException.class,
                () -> gate.authorize(APP_KEY, "GET", "/open/v1/orders")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void multipleAllowedRowsFailClosed() throws Exception {
        when(resultSet.next()).thenReturn(true, true);
        when(resultSet.getString("decision")).thenReturn("ALLOWED");
        when(resultSet.getObject("app_id", UUID.class)).thenReturn(APP_ID);
        when(resultSet.getObject("api_id", UUID.class)).thenReturn(API_ID);
        when(resultSet.getObject("api_version_id", UUID.class)).thenReturn(VERSION_ID);
        when(resultSet.getObject("tenant_id", UUID.class)).thenReturn(TENANT_ID);
        when(resultSet.getString("visibility")).thenReturn("PLATFORM_PUBLIC");
        when(resultSet.getString("route_params")).thenReturn("{}");

        ApiAuthorizationException exception = assertThrows(
                ApiAuthorizationException.class,
                () -> gate.authorize(APP_KEY, "GET", "/open/v1/orders")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    @Test
    void databaseFailureIsRetryableStoreUnavailable() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("database down"));

        ApiAuthorizationException exception = assertThrows(
                ApiAuthorizationException.class,
                () -> gate.authorize(APP_KEY, "GET", "/open/v1/orders")
        );

        assertEquals("AUTHORIZATION_STORE_UNAVAILABLE", exception.code());
        assertTrue(exception.retryable());
    }

    @Test
    void malformedRouteParametersFailClosed() throws Exception {
        when(resultSet.next()).thenReturn(true, false);
        when(resultSet.getString("decision")).thenReturn("ALLOWED");
        when(resultSet.getObject("app_id", UUID.class)).thenReturn(APP_ID);
        when(resultSet.getObject("api_id", UUID.class)).thenReturn(API_ID);
        when(resultSet.getObject("api_version_id", UUID.class)).thenReturn(VERSION_ID);
        when(resultSet.getObject("tenant_id", UUID.class)).thenReturn(TENANT_ID);
        when(resultSet.getString("visibility")).thenReturn("PLATFORM_PUBLIC");
        when(resultSet.getString("route_params")).thenReturn("[]");

        ApiAuthorizationException exception = assertThrows(
                ApiAuthorizationException.class,
                () -> gate.authorize(APP_KEY, "GET", "/open/v1/orders")
        );

        assertEquals("INTERNAL_CONFIGURATION", exception.code());
    }

    private void assertDecision(String decision, boolean retryable) throws Exception {
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString("decision")).thenReturn(decision);

        ApiAuthorizationException exception = assertThrows(
                ApiAuthorizationException.class,
                () -> gate.authorize(APP_KEY, "GET", "/open/v1/orders")
        );

        if ("UNKNOWN".equals(decision)) {
            assertEquals("INTERNAL_CONFIGURATION", exception.code());
        } else {
            assertEquals(decision, exception.code());
        }
        assertEquals(retryable, exception.retryable());
    }
}
