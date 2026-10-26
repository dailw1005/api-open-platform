package com.apiproject.app.security;

public record GatewayDatabaseRoleStatus(
        String roleName,
        boolean functionExecute,
        boolean superuser,
        boolean bypassRls,
        boolean directCredentialAccess
) {
}
