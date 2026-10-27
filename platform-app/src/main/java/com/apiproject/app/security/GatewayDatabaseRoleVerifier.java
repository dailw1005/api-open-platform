package com.apiproject.app.security;

import com.apiproject.gateway.security.CredentialResolutionException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;

public final class GatewayDatabaseRoleVerifier {

    private static final String ROLE_CHECK_SQL = """
            SELECT
                current_user,
                r.rolsuper,
                r.rolbypassrls,
                has_function_privilege(
                    current_user,
                    'public.auth_resolve_active_credential(text)',
                    'EXECUTE'
                ),
                has_function_privilege(
                    current_user,
                    'public.auth_authorize_public_api(text,text,text)',
                    'EXECUTE'
                ),
                has_function_privilege(
                    current_user,
                    'public.auth_resolve_post_auth_policies(uuid,uuid)',
                    'EXECUTE'
                ),
                has_function_privilege(
                    current_user,
                    'public.auth_resolve_api_target(uuid,uuid)',
                    'EXECUTE'
                ),
                has_table_privilege(
                    current_user,
                    'public.app_credential',
                    'SELECT,INSERT,UPDATE,DELETE'
                )
            FROM pg_roles AS r
            WHERE r.rolname = current_user
            """;

    private final DataSource dataSource;

    public GatewayDatabaseRoleVerifier(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public GatewayDatabaseRoleStatus verify() {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(ROLE_CHECK_SQL)) {
            if (!resultSet.next()) {
                throw configurationError("Gateway database role was not found");
            }

            String roleName = resultSet.getString(1);
            boolean superuser = resultSet.getBoolean(2);
            boolean bypassRls = resultSet.getBoolean(3);
            boolean credentialFunctionExecute = resultSet.getBoolean(4);
            boolean authorizationFunctionExecute = resultSet.getBoolean(5);
            boolean policyFunctionExecute = resultSet.getBoolean(6);
            boolean targetFunctionExecute = resultSet.getBoolean(7);
            boolean directCredentialAccess = resultSet.getBoolean(8);

            if (superuser) {
                throw configurationError(
                        "Gateway database role must not be superuser"
                );
            }
            if (bypassRls) {
                throw configurationError(
                        "Gateway database role must not have BYPASSRLS"
                );
            }
            if (!credentialFunctionExecute) {
                throw configurationError(
                        "Gateway database role lacks credential lookup EXECUTE"
                );
            }
            if (!authorizationFunctionExecute) {
                throw configurationError(
                        "Gateway database role lacks authorization EXECUTE"
                );
            }
            if (!policyFunctionExecute) {
                throw configurationError(
                        "Gateway database role lacks post-auth policy EXECUTE"
                );
            }
            if (!targetFunctionExecute) {
                throw configurationError(
                        "Gateway database role lacks target resolution EXECUTE"
                );
            }
            if (directCredentialAccess) {
                throw configurationError(
                        "Gateway database role has sensitive table privileges"
                );
            }
            return new GatewayDatabaseRoleStatus(
                    roleName,
                    credentialFunctionExecute,
                    authorizationFunctionExecute,
                    policyFunctionExecute,
                    targetFunctionExecute,
                    superuser,
                    bypassRls,
                    directCredentialAccess
            );
        } catch (SQLException exception) {
            throw configurationError(
                    "Unable to verify gateway database role",
                    exception
            );
        }
    }

    private CredentialResolutionException configurationError(String message) {
        return configurationError(message, null);
    }

    private CredentialResolutionException configurationError(
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
}
