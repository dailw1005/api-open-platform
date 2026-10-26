package com.apiproject.orchestration;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class FlowValidator {

    private static final String SCHEMA_RESOURCE =
            "/contracts/dsl/orchestration-dsl-v1.schema.json";

    private final JsonSchema schema;

    private FlowValidator(JsonSchema schema) {
        this.schema = Objects.requireNonNull(schema, "schema");
    }

    public static FlowValidator createDefault() {
        try (InputStream input = FlowValidator.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Missing classpath resource: " + SCHEMA_RESOURCE);
            }
            JsonSchemaFactory factory = JsonSchemaFactory.getInstance(
                    SpecVersion.VersionFlag.V202012
            );
            return new FlowValidator(factory.getSchema(input));
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to load orchestration DSL schema", exception);
        }
    }

    public FlowValidationResult validate(JsonNode dsl, ApiMetadataResolver resolver) {
        Objects.requireNonNull(dsl, "dsl");
        Objects.requireNonNull(resolver, "resolver");

        List<FlowValidationIssue> issues = new ArrayList<>();
        schema.validate(dsl).stream()
                .map(FlowValidator::schemaIssue)
                .forEach(issues::add);
        if (!issues.isEmpty()) {
            return new FlowValidationResult(issues);
        }

        ValidationContext context = new ValidationContext(dsl, resolver, issues);
        context.validateDocument();
        return new FlowValidationResult(issues);
    }

    private static FlowValidationIssue schemaIssue(ValidationMessage message) {
        String pointer = message.getInstanceLocation() == null
                ? "/"
                : message.getInstanceLocation().toString();
        return new FlowValidationIssue(
                pointer,
                "DSL_SCHEMA_INVALID",
                message.getMessage()
        );
    }

    private static final class ValidationContext {
        private final JsonNode root;
        private final ApiMetadataResolver resolver;
        private final List<FlowValidationIssue> issues;
        private final Map<String, String> nodePointers = new LinkedHashMap<>();
        private final Set<String> declaredVariables = new LinkedHashSet<>();
        private final Set<String> checkedReferences = new HashSet<>();

        private ValidationContext(
                JsonNode root,
                ApiMetadataResolver resolver,
                List<FlowValidationIssue> issues
        ) {
            this.root = root;
            this.resolver = resolver;
            this.issues = issues;
        }

        private void validateDocument() {
            collectMappingVariables(root.path("defaults"));
            collectMappingVariables(root.path("outputMapping"));
            collectStepDeclarations(root.path("steps"));
            int documentTimeout = root.path("timeoutMs").asInt();
            validateSteps(root.path("steps"), "/steps", documentTimeout);
            validateReferencesInValue(
                    root.path("defaults"),
                    "/defaults"
            );
            validateReferencesInValue(
                    root.path("outputMapping"),
                    "/outputMapping"
            );
        }

        private void collectStepDeclarations(JsonNode steps) {
            if (steps == null || !steps.isArray()) {
                return;
            }
            for (JsonNode step : steps) {
                collectMappingVariables(step.path("assign"));
                collectMappingVariables(step.path("outputMapping"));
                switch (step.path("type").asText()) {
                    case "if" -> {
                        collectStepDeclarations(step.path("then"));
                        collectStepDeclarations(step.path("else"));
                    }
                    case "parallel" -> step.path("branches").forEach(
                            branch -> collectStepDeclarations(branch.path("steps"))
                    );
                    case "try" -> {
                        collectStepDeclarations(step.path("steps"));
                        collectStepDeclarations(step.path("catch"));
                    }
                    default -> {
                        // Other node types do not contain nested steps.
                    }
                }
            }
        }

        private void collectMappingVariables(JsonNode mapping) {
            if (mapping == null || !mapping.isObject()) {
                return;
            }
            mapping.fieldNames().forEachRemaining(name -> {
                if (name.startsWith("vars/")) {
                    declaredVariables.add(name);
                }
            });
        }

        private void validateSteps(JsonNode steps, String pointer, int parentTimeout) {
            if (steps == null || !steps.isArray()) {
                return;
            }
            for (int index = 0; index < steps.size(); index++) {
                JsonNode step = steps.get(index);
                String stepPointer = pointer + "/" + index;
                validateStep(step, stepPointer, parentTimeout);
            }
        }

        private void validateStep(JsonNode step, String pointer, int parentTimeout) {
            String type = step.path("type").asText();
            String id = step.path("id").asText();
            if (!id.isBlank()) {
                String previous = nodePointers.putIfAbsent(id, pointer);
                if (previous != null) {
                    issues.add(issue(
                            pointer + "/id",
                            "DSL_DUPLICATE_NODE_ID",
                            "Node identifier '" + id + "' is duplicated"
                    ));
                }
            }

            int nodeTimeout = step.path("timeoutMs").asInt(parentTimeout);
            if (nodeTimeout > parentTimeout) {
                issues.add(issue(
                        pointer + "/timeoutMs",
                        "DSL_TIMEOUT_BUDGET",
                        "Node timeout exceeds parent scope timeout"
                ));
            }

            switch (type) {
                case "api" -> validateApiNode(step, pointer);
                case "if" -> {
                    validateSteps(step.path("then"), pointer + "/then", nodeTimeout);
                    validateSteps(step.path("else"), pointer + "/else", nodeTimeout);
                }
                case "parallel" -> {
                    validateParallelNode(step, pointer, nodeTimeout);
                }
                case "try" -> {
                    validateSteps(step.path("steps"), pointer + "/steps", nodeTimeout);
                    validateSteps(step.path("catch"), pointer + "/catch", nodeTimeout);
                }
                case "set_vars", "end" -> {
                    // No nested steps.
                }
                default -> {
                    // Structural schema validation rejects unknown node types.
                }
            }

            validateReferencesInValue(step.path("request"), pointer + "/request");
            validateReferencesInValue(step.path("condition"), pointer + "/condition");
            validateReferencesInValue(step.path("assign"), pointer + "/assign");
            validateReferencesInValue(step.path("outputMapping"), pointer + "/outputMapping");
        }

        private void validateApiNode(JsonNode step, String pointer) {
            String apiRef = step.path("apiRef").asText();
            Optional<ApiMetadata> resolved = resolver.resolve(apiRef);
            if (resolved.isEmpty()) {
                issues.add(issue(
                        pointer + "/apiRef",
                        "DSL_UNKNOWN_API",
                        "API reference cannot be resolved: " + apiRef
                ));
                return;
            }
            ApiMetadata metadata = resolved.get();
            if (metadata.kind() == ApiKind.ORCHESTRATION) {
                issues.add(issue(
                        pointer + "/apiRef",
                        "DSL_NESTED_ORCHESTRATION",
                        "MVP orchestration nodes cannot reference another orchestration"
                ));
            }
            if (step.has("retry") && !metadata.idempotent()) {
                JsonNode idempotency = step.path("idempotency");
                boolean safeRetry = "platform".equals(idempotency.path("mode").asText())
                        && "Idempotency-Key".equals(idempotency.path("header").asText());
                if (!safeRetry) {
                    issues.add(issue(
                            pointer + "/retry",
                            "DSL_UNSAFE_RETRY",
                            "Non-idempotent API retry requires platform idempotency"
                    ));
                }
            }
        }

        private void validateParallelNode(JsonNode step, String pointer, int timeout) {
            List<BranchWrite> writes = new ArrayList<>();
            JsonNode branches = step.path("branches");
            for (int branchIndex = 0; branchIndex < branches.size(); branchIndex++) {
                JsonNode branch = branches.get(branchIndex);
                String branchPointer = pointer + "/branches/" + branchIndex;
                validateSteps(branch.path("steps"), branchPointer + "/steps", timeout);
                for (String path : collectBranchWrites(branch)) {
                    writes.add(new BranchWrite(branchIndex, path));
                }
            }
            for (int leftIndex = 0; leftIndex < writes.size(); leftIndex++) {
                BranchWrite left = writes.get(leftIndex);
                for (int rightIndex = leftIndex + 1; rightIndex < writes.size(); rightIndex++) {
                    BranchWrite right = writes.get(rightIndex);
                    if (left.branchIndex() != right.branchIndex()
                            && overlaps(left.path(), right.path())) {
                    issues.add(issue(
                            pointer + "/branches",
                            "DSL_PARALLEL_VAR_CONFLICT",
                                "Parallel branches write overlapping variable paths: "
                                        + left.path() + " and " + right.path()
                    ));
                        return;
                }
                }
            }
        }

        private boolean overlaps(String left, String right) {
            return left.equals(right)
                    || left.startsWith(right + "/")
                    || right.startsWith(left + "/");
        }

        private Set<String> collectBranchWrites(JsonNode branch) {
            Set<String> writes = new LinkedHashSet<>();
            collectStepWrites(branch.path("steps"), writes);
            return writes;
        }

        private void collectStepWrites(JsonNode steps, Set<String> writes) {
            if (steps == null || !steps.isArray()) {
                return;
            }
            for (JsonNode step : steps) {
                collectMappingWrites(step.path("assign"), writes);
                collectMappingWrites(step.path("outputMapping"), writes);
                switch (step.path("type").asText()) {
                    case "if" -> {
                        collectStepWrites(step.path("then"), writes);
                        collectStepWrites(step.path("else"), writes);
                    }
                    case "parallel" -> step.path("branches").forEach(
                            branch -> collectStepWrites(branch.path("steps"), writes)
                    );
                    case "try" -> {
                        collectStepWrites(step.path("steps"), writes);
                        collectStepWrites(step.path("catch"), writes);
                    }
                    default -> {
                        // Other node types do not contain nested steps.
                    }
                }
            }
        }

        private void collectMappingWrites(JsonNode mapping, Set<String> writes) {
            if (mapping == null || !mapping.isObject()) {
                return;
            }
            mapping.fieldNames().forEachRemaining(name -> {
                if (name.startsWith("vars/")) {
                    writes.add(name);
                }
            });
        }

        private void validateReferencesInValue(JsonNode node, String pointer) {
            if (node == null || node.isMissingNode() || node.isNull()) {
                return;
            }
            if (node.isObject()) {
                JsonNode reference = node.get("$ref");
                if (reference != null && reference.isTextual()) {
                    validateReference(reference.asText(), pointer + "/$ref");
                    return;
                }
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    validateReferencesInValue(
                            field.getValue(),
                            pointer + "/" + escapePointer(field.getKey())
                    );
                }
                return;
            }
            if (node.isArray()) {
                for (int index = 0; index < node.size(); index++) {
                    validateReferencesInValue(
                            node.get(index),
                            pointer + "/" + index
                    );
                }
            }
        }

        private void validateReference(String reference, String pointer) {
            if (!checkedReferences.add(pointer + "=" + reference)) {
                return;
            }
            String[] segments = reference.split("/", 2);
            if (segments.length != 2 || segments[1].isBlank()) {
                issues.add(issue(
                        pointer,
                        "DSL_UNRESOLVED_REFERENCE",
                        "Reference must use <namespace>/<pointer>: " + reference
                ));
                return;
            }
            String namespace = segments[0];
            String path = segments[1];
            if ("input".equals(namespace) || "sys".equals(namespace)) {
                return;
            }
            if ("steps".equals(namespace)) {
                String nodeId = path.split("/", 2)[0];
                if (!nodePointers.containsKey(nodeId)) {
                    issues.add(issue(
                            pointer,
                            "DSL_UNRESOLVED_REFERENCE",
                            "Unknown step reference: " + reference
                    ));
                }
                return;
            }
            if ("vars".equals(namespace)) {
                String variablePath = "vars/" + path;
                boolean declared = declaredVariables.stream()
                        .anyMatch(declaredPath ->
                                variablePath.equals(declaredPath)
                                        || variablePath.startsWith(declaredPath + "/"));
                if (!declared) {
                    issues.add(issue(
                            pointer,
                            "DSL_UNRESOLVED_REFERENCE",
                            "Unknown variable reference: " + reference
                    ));
                }
                return;
            }
            issues.add(issue(
                    pointer,
                    "DSL_UNRESOLVED_REFERENCE",
                    "Unsupported reference namespace: " + namespace
            ));
        }

        private FlowValidationIssue issue(String pointer, String code, String message) {
            return new FlowValidationIssue(pointer, code, message);
        }

        private String escapePointer(String segment) {
            return segment.replace("~", "~0").replace("/", "~1");
        }

        private record BranchWrite(int branchIndex, String path) {
        }
    }
}
