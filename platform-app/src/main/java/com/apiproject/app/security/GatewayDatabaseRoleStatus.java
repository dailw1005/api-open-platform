package com.apiproject.app.security;

public record GatewayDatabaseRoleStatus(
        String roleName,
        boolean credentialFunctionExecute,
        boolean authorizationFunctionExecute,
        boolean policyFunctionExecute,
        boolean targetFunctionExecute,
        boolean superuser,
        boolean bypassRls,
        boolean directCredentialAccess
) {
}
