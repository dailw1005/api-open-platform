package com.apiproject.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenApiContractTest {

    private static final Set<String> REQUIRED_OPERATIONS = Set.of(
            "createAdminSession",
            "deleteAdminSession",
            "createDeveloperSession",
            "deleteDeveloperSession",
            "listTenants",
            "createTenant",
            "getTenant",
            "updateTenant",
            "inviteUser",
            "createRoleBinding",
            "deleteRoleBinding",
            "listUpstreamEndpoints",
            "createUpstreamEndpoint",
            "getUpstreamEndpoint",
            "updateUpstreamEndpoint",
            "createUpstreamEnvironment",
            "updateUpstreamEnvironment",
            "listApis",
            "createApiDefinition",
            "getApiDefinition",
            "updateApiDefinition",
            "createApiVersion",
            "deprecateApi",
            "offlineApi",
            "createApiPublication",
            "rollbackApiPublication",
            "createRateLimitPolicy",
            "updateRateLimitPolicy",
            "createQuotaPolicy",
            "updateQuotaPolicy",
            "createPriceRule",
            "updatePriceRule",
            "reviewOrchestration",
            "publishOrchestration",
            "suspendApp",
            "revokeApp",
            "listAuditLogs",
            "listPublishedApis",
            "getPublishedApi",
            "listVisibleApps",
            "createApp",
            "getVisibleApp",
            "updateOwnApp",
            "createAppCredential",
            "rotateAppCredential",
            "revokeAppCredential",
            "createApiGrant",
            "revokeApiGrant",
            "getAppUsage",
            "listAppRequestLogs",
            "listOrchestrations",
            "createOrchestration",
            "getOrchestration",
            "updateOrchestrationDraft",
            "validateOrchestrationDraft",
            "createOrchestrationTestRun",
            "getOrchestrationTestRun",
            "submitOrchestration",
            "invokePublicApiGet",
            "invokePublicApiPost",
            "invokePublicApiPut",
            "invokePublicApiPatch",
            "invokePublicApiDelete"
    );

    private static final Set<String> REQUIRED_EXTENSIONS = Set.of(
            "x-auth-kind",
            "x-required-role",
            "x-tenant-scope",
            "x-csrf-required",
            "x-idempotency",
            "x-contract-version"
    );

    private static final Set<String> HMAC_HEADERS = Set.of(
            "X-Signature-Version",
            "X-App-Key",
            "X-Timestamp",
            "X-Nonce",
            "X-Signature"
    );

    private static OpenAPI openApi;
    private static JsonNode rawContract;
    private static Map<String, Operation> operations;
    private static Map<String, List<Parameter>> pathLevelParameters;

    @BeforeAll
    static void loadContract() {
        Path contractPath = Path.of(
                System.getProperty("contracts.dir"),
                "openapi",
                "openapi.yaml"
        );
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);
        try {
            rawContract = new ObjectMapper(new YAMLFactory()).readTree(contractPath.toFile());
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read raw OpenAPI contract", exception);
        }
        SwaggerParseResult result = new OpenAPIV3Parser()
                .readLocation(contractPath.toUri().toString(), null, options);

        assertNotNull(result.getOpenAPI(), () -> "OpenAPI parse failed: " + result.getMessages());
        assertTrue(result.getMessages().isEmpty(), () -> "OpenAPI messages: " + result.getMessages());
        openApi = result.getOpenAPI();
        pathLevelParameters = new HashMap<>();
        operations = indexOperations(openApi);
    }

    @Test
    void parsesWithoutErrors() {
        assertEquals("3.1.0", openApi.getOpenapi());
        assertTrue(openApi.getPaths().size() >= 40);
    }

    @Test
    void containsRequiredOperations() {
        assertEquals(REQUIRED_OPERATIONS, operations.keySet());
    }

    @Test
    void allOperationsDeclareContractExtensions() {
        operations.forEach((operationId, operation) -> {
            Map<String, Object> extensions = operation.getExtensions();
            assertNotNull(extensions, operationId);
            REQUIRED_EXTENSIONS.forEach(extension ->
                    assertTrue(extensions.containsKey(extension), operationId + " missing " + extension));
        });
    }

    @Test
    void sessionWritesRequireSessionAndCsrfSecurity() {
        operations.forEach((operationId, operation) -> {
            if (Boolean.TRUE.equals(operation.getExtensions().get("x-csrf-required"))) {
                Set<String> schemes = securitySchemes(operation);
                assertTrue(schemes.contains("sessionCookie"), operationId);
                assertTrue(schemes.contains("csrfToken"), operationId);
            }
        });
    }

    @Test
    void viewerCannotPerformWriteOperationsExceptLogout() {
        operations.forEach((operationId, operation) -> {
            String role = String.valueOf(operation.getExtensions().get("x-required-role"));
            boolean csrfRequired = Boolean.TRUE.equals(
                    operation.getExtensions().get("x-csrf-required")
            );
            if (role.contains("VIEWER") && csrfRequired) {
                assertEquals("deleteDeveloperSession", operationId);
            }
        });
    }

    @Test
    void publicOperationsDeclareHmacAuthenticationAndHeaders() {
        operations.values().stream()
                .filter(operation -> "HMAC_V1".equals(operation.getExtensions().get("x-auth-kind")))
                .forEach(operation -> {
                    assertTrue(securitySchemes(operation).contains("hmacV1"));
                    List<Parameter> parameters = new ArrayList<>(
                            pathLevelParameters.getOrDefault(operation.getOperationId(), List.of())
                    );
                    if (operation.getParameters() != null) {
                        parameters.addAll(operation.getParameters());
                    }
                    Set<String> declaredHeaders = parameters.stream()
                            .map(Parameter::getName)
                            .collect(java.util.stream.Collectors.toSet());
                    assertTrue(declaredHeaders.containsAll(HMAC_HEADERS), declaredHeaders.toString());
                });
    }

    @Test
    void publicOperationsDocumentAuthorizationRateLimitAndFailureResponses() {
        operations.values().stream()
                .filter(operation -> "HMAC_V1".equals(operation.getExtensions().get("x-auth-kind")))
                .forEach(operation -> {
                    assertTrue(operation.getResponses().containsKey("403"),
                            operation.getOperationId() + " missing 403");
                    assertTrue(operation.getResponses().containsKey("404"),
                            operation.getOperationId() + " missing 404");
                    assertTrue(operation.getResponses().containsKey("429"),
                            operation.getOperationId() + " missing 429");
                    assertTrue(operation.getResponses().containsKey("413"),
                            operation.getOperationId() + " missing 413");
                    assertTrue(operation.getResponses().containsKey("500"),
                            operation.getOperationId() + " missing 500");
                });
    }

    @Test
    void errorResponsesUseSharedEnvelope() {
        rawContract.path("paths").fields().forEachRemaining(pathEntry -> {
            String path = pathEntry.getKey();
            pathEntry.getValue().fields().forEachRemaining(operationEntry -> {
                JsonNode responses = operationEntry.getValue().get("responses");
                if (responses == null) {
                    return;
                }
                responses.fields().forEachRemaining(responseEntry -> {
                    String status = responseEntry.getKey();
                    if (!status.startsWith("4") && !status.startsWith("5")) {
                        return;
                    }
                    assertTrue(errorResponseUsesEnvelope(responseEntry.getValue()),
                            path + " " + operationEntry.getKey() + " response " + status
                                    + " does not reference an ErrorResponse component");
                });
            });
        });
    }

    private static Map<String, Operation> indexOperations(OpenAPI document) {
        Map<String, Operation> indexed = new HashMap<>();
        document.getPaths().forEach((path, pathItem) -> {
            List<Parameter> inheritedParameters = pathItem.getParameters() == null
                    ? List.of()
                    : List.copyOf(pathItem.getParameters());
            pathItem.readOperationsMap().forEach((method, operation) -> {
                    assertNotNull(operation.getOperationId(), path + " " + method);
                    assertFalse(operation.getOperationId().isBlank(), path + " " + method);
                    Operation previous = indexed.put(operation.getOperationId(), operation);
                    pathLevelParameters.put(operation.getOperationId(), inheritedParameters);
                    assertTrue(previous == null,
                            () -> "Duplicate operationId: " + operation.getOperationId());
                });
        });
        return indexed;
    }

    private static Set<String> securitySchemes(Operation operation) {
        if (operation.getSecurity() == null) {
            return Set.of();
        }
        Set<String> schemes = new HashSet<>();
        for (SecurityRequirement requirement : operation.getSecurity()) {
            schemes.addAll(requirement.keySet());
        }
        return schemes;
    }

    private static boolean errorResponseUsesEnvelope(JsonNode response) {
        JsonNode reference = response.get("$ref");
        if (reference == null || !reference.asText().startsWith("#/components/responses/")) {
            return false;
        }
        String componentName = reference.asText().substring(
                "#/components/responses/".length()
        );
        JsonNode schemaReference = rawContract.path("components")
                .path("responses")
                .path(componentName)
                .path("content")
                .path("application/json")
                .path("schema")
                .path("$ref");
        return schemaReference.isTextual()
                && schemaReference.asText().toLowerCase(Locale.ROOT)
                .endsWith("/errorresponse");
    }
}
