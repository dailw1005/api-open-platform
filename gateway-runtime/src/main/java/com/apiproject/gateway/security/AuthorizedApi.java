package com.apiproject.gateway.security;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

public record AuthorizedApi(
        UUID appId,
        UUID apiId,
        UUID apiVersionId,
        UUID tenantId,
        String visibility,
        Map<String, String> routeParameters
) {

    private static final Pattern PARAMETER_NAME =
            Pattern.compile("^[A-Za-z][A-Za-z0-9_]{0,63}$");
    private static final Pattern PARAMETER_VALUE =
            Pattern.compile("^[A-Za-z0-9._~-]{1,256}$");

    public AuthorizedApi(
            UUID appId,
            UUID apiId,
            UUID apiVersionId,
            UUID tenantId,
            String visibility
    ) {
        this(appId, apiId, apiVersionId, tenantId, visibility, Map.of());
    }

    public AuthorizedApi {
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(apiId, "apiId");
        Objects.requireNonNull(apiVersionId, "apiVersionId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(visibility, "visibility");
        Objects.requireNonNull(routeParameters, "routeParameters");
        routeParameters.forEach((name, value) -> {
            if (name == null || !PARAMETER_NAME.matcher(name).matches()) {
                throw new IllegalArgumentException(
                        "route parameter name is invalid"
                );
            }
            if (value == null || !PARAMETER_VALUE.matcher(value).matches()) {
                throw new IllegalArgumentException(
                        "route parameter value is invalid"
                );
            }
        });
        routeParameters = Map.copyOf(routeParameters);
    }
}
