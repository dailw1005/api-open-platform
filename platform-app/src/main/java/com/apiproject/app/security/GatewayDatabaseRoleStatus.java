package com.apiproject.app.security;

public record GatewayDatabaseRoleStatus(
        String roleName,
        boolean credentialFunctionExecute,
        boolean authorizationFunctionExecute,
        boolean superuser,
        boolean bypassRls,
        boolean directCredentialAccess
) {
}
