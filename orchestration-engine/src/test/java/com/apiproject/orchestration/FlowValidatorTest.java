package com.apiproject.orchestration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FlowValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static JsonNode validDsl;
    private static FlowValidator validator;

    @BeforeAll
    static void loadFixture() throws IOException {
        Path fixture = Path.of(
                System.getProperty("contracts.dir"),
                "examples",
                "orchestration-v1.valid.json"
        );
        validDsl = MAPPER.readTree(fixture.toFile());
        validator = FlowValidator.createDefault();
    }

    @Test
    void validExamplePasses() {
        FlowValidationResult result = validator.validate(validDsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void duplicateNodeIdentifiersAreRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/steps/0/steps/2")).put("id", "getUser");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_DUPLICATE_NODE_ID", "/steps/0/steps/2/id");
    }

    @Test
    void unresolvedVariableReferenceIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "vars/missing/items"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_UNRESOLVED_REFERENCE", "/outputMapping/orders/$ref");
    }

    @Test
    void nestedOrchestrationReferenceIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ApiMetadataResolver resolver = apiRef -> Optional.of(
                new ApiMetadata(
                        apiRef,
                        apiRef.startsWith("order-service/")
                                ? ApiKind.ORCHESTRATION
                                : ApiKind.PROXY,
                        true
                )
        );

        FlowValidationResult result = validator.validate(dsl, resolver);

        assertIssue(result, "DSL_NESTED_ORCHESTRATION", "/steps/0/steps/1/then/0/branches/0/steps/0/apiRef");
    }

    @Test
    void unsafeRetryOnNonIdempotentApiIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ApiMetadataResolver resolver = apiRef -> Optional.of(
                new ApiMetadata(
                        apiRef,
                        ApiKind.PROXY,
                        !apiRef.startsWith("user-service/get-user@")
                )
        );

        FlowValidationResult result = validator.validate(dsl, resolver);

        assertIssue(result, "DSL_UNSAFE_RETRY", "/steps/0/steps/0/retry");
    }

    @Test
    void childTimeoutExceedingParentIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/steps/0")).put("timeoutMs", 1000);

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_TIMEOUT_BUDGET", "/steps/0/steps/0/timeoutMs");
    }

    @Test
    void parallelConflictingVariableWritesAreRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode firstBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/0/steps/0"
        );
        ObjectNode secondBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/1/steps/0"
        );
        replaceWithSetVars(firstBranch, "writeOrders", "vars/shared");
        replaceWithSetVars(secondBranch, "writePoints", "vars/shared");
        rewireParallelOutputMapping(dsl, "vars/shared", "vars/shared");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_PARALLEL_VAR_CONFLICT", "/steps/0/steps/1/then/0/branches");
    }

    @Test
    void overlappingParallelVariableWritesAreRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode firstBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/0/steps/0"
        );
        ObjectNode secondBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/1/steps/0"
        );
        replaceWithSetVars(firstBranch, "writeOrders", "vars/shared");
        replaceWithSetVars(secondBranch, "writePoints", "vars/shared/child");
        rewireParallelOutputMapping(dsl, "vars/shared", "vars/shared/child");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_PARALLEL_VAR_CONFLICT", "/steps/0/steps/1/then/0/branches");
    }

    @Test
    void unknownApiReferenceIsRejected() {
        ApiMetadataResolver resolver = apiRef -> Optional.empty();

        FlowValidationResult result = validator.validate(validDsl, resolver);

        assertIssue(result, "DSL_UNKNOWN_API", "/steps/0/steps/0/apiRef");
    }

    @Test
    void structurallyInvalidDslIsRejectedBeforeSemanticChecks() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode scriptStep = (ObjectNode) dsl.at("/steps/0/steps/0");
        scriptStep.removeAll();
        scriptStep.put("id", "unsafeScript");
        scriptStep.put("type", "script");
        scriptStep.put("source", "return 1");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.hasCode("DSL_SCHEMA_INVALID"), result.issues().toString());
    }

    @Test
    void safeNonIdempotentRetryWithPlatformKeyPasses() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/steps/0/steps/0")).putObject("idempotency")
                .put("mode", "platform")
                .put("header", "Idempotency-Key");
        ApiMetadataResolver resolver = apiRef -> Optional.of(new ApiMetadata(
                apiRef,
                ApiKind.PROXY,
                false
        ));

        FlowValidationResult result = validator.validate(dsl, resolver);

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void unsupportedReferenceNamespaceIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "secrets/upstreamToken"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_UNRESOLVED_REFERENCE", "/outputMapping/orders/$ref");
    }

    @Test
    void sysReferenceIsAccepted() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "sys/requestId"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void unknownStepReferenceIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "steps/missing/body"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_UNRESOLVED_REFERENCE", "/outputMapping/orders/$ref");
    }

    @Test
    void emptyReferencePointerIsRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "vars/"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_UNRESOLVED_REFERENCE", "/outputMapping/orders/$ref");
    }

    @Test
    void referenceInsideArrayIsValidated() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode request = (ObjectNode) dsl.at("/steps/0/steps/0/request");
        request.putArray("body").addObject().put("$ref", "input/userId");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void reverseOverlappingParallelVariableWritesAreRejected() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode firstBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/0/steps/0"
        );
        ObjectNode secondBranch = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/1/steps/0"
        );
        replaceWithSetVars(firstBranch, "writeOrders", "vars/shared/child");
        replaceWithSetVars(secondBranch, "writePoints", "vars/shared");
        rewireParallelOutputMapping(dsl, "vars/shared/child", "vars/shared");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_PARALLEL_VAR_CONFLICT", "/steps/0/steps/1/then/0/branches");
    }

    @Test
    void duplicateReferenceIsValidatedOnlyOnce() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/outputMapping/orders")).put("$ref", "vars/degraded");
        ((ObjectNode) dsl.at("/outputMapping/points")).put("$ref", "vars/degraded");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void sequentialWritesInOneParallelBranchDoNotConflict() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode parallel = (ObjectNode) dsl.at("/steps/0/steps/1/then/0");
        ObjectNode firstBranch = (ObjectNode) parallel.at("/branches/0");
        ObjectNode secondBranch = (ObjectNode) parallel.at("/branches/1");

        ArrayNode firstSteps = firstBranch.putArray("steps");
        firstSteps.add(setVarsStep("writeA", "vars/a"));
        firstSteps.add(setVarsStep("writeNestedA", "vars/a/child"));
        ArrayNode secondSteps = secondBranch.putArray("steps");
        secondSteps.add(setVarsStep("writeB", "vars/b"));
        ((ObjectNode) parallel.at("/outputMapping/vars~1orders"))
                .put("$ref", "vars/a");
        ((ObjectNode) parallel.at("/outputMapping/vars~1points"))
                .put("$ref", "vars/b");

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    @Test
    void inputSchemaDefaultsDoNotDeclareRuntimeVariables() throws IOException {
        ObjectNode dsl = copyValid();
        ((ObjectNode) dsl.at("/inputSchema"))
                .putObject("defaults")
                .put("vars/missing", "not-a-runtime-variable");
        ((ObjectNode) dsl.at("/outputMapping/orders")).put(
                "$ref",
                "vars/missing/items"
        );

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertIssue(result, "DSL_UNRESOLVED_REFERENCE", "/outputMapping/orders/$ref");
    }

    @Test
    void requestBodyAssignFieldIsNotAVariableWrite() throws IOException {
        ObjectNode dsl = copyValid();
        ObjectNode orderRequest = (ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/0/steps/0/request"
        );
        orderRequest.putObject("body")
                .putObject("assign")
                .putObject("vars/shared")
                .put("value", "business-data");
        ArrayNode pointsSteps = (ArrayNode) dsl.at(
                "/steps/0/steps/1/then/0/branches/1/steps"
        );
        pointsSteps.add(setVarsStep("writeShared", "vars/shared"));

        FlowValidationResult result = validator.validate(dsl, defaultResolver());

        assertTrue(result.valid(), result.issues().toString());
    }

    private static ApiMetadataResolver defaultResolver() {
        return apiRef -> Optional.of(new ApiMetadata(
                apiRef,
                ApiKind.PROXY,
                true
        ));
    }

    private static ObjectNode copyValid() throws IOException {
        return (ObjectNode) MAPPER.readTree(MAPPER.writeValueAsBytes(validDsl));
    }

    private static void replaceWithSetVars(ObjectNode step, String id, String path) {
        step.removeAll();
        step.put("id", id);
        step.put("type", "set_vars");
        ObjectNode assign = MAPPER.createObjectNode();
        assign.putObject(path).put("value", id);
        step.set("assign", assign);
    }

    private static void rewireParallelOutputMapping(
            ObjectNode dsl,
            String firstReference,
            String secondReference
    ) {
        ((ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/outputMapping/vars~1orders"
        )).put("$ref", firstReference);
        ((ObjectNode) dsl.at(
                "/steps/0/steps/1/then/0/outputMapping/vars~1points"
        )).put("$ref", secondReference);
    }

    private static ObjectNode setVarsStep(String id, String path) {
        ObjectNode step = MAPPER.createObjectNode();
        step.put("id", id);
        step.put("type", "set_vars");
        step.putObject("assign").putObject(path).put("value", id);
        return step;
    }

    private static void assertIssue(
            FlowValidationResult result,
            String code,
            String pointer
    ) {
        assertFalse(result.valid(), result.issues().toString());
        assertTrue(
                result.issues().stream().anyMatch(issue ->
                        issue.code().equals(code) && issue.pointer().equals(pointer)),
                () -> "Expected " + code + " at " + pointer + " but got " + result.issues()
        );
    }
}
