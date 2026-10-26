package com.apiproject.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DslSchemaContractTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static Path contractsDirectory;
    private static JsonSchema schema;

    @BeforeAll
    static void loadSchema() throws IOException {
        contractsDirectory = Path.of(System.getProperty("contracts.dir"));
        JsonNode schemaNode = readJson("dsl/orchestration-dsl-v1.schema.json");
        assertEquals(
                "https://json-schema.org/draft/2020-12/schema",
                schemaNode.get("$schema").asText()
        );
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(
                SpecVersion.VersionFlag.V202012
        );
        schema = factory.getSchema(schemaNode);
        assertNotNull(schema);
    }

    @Test
    void schemaUsesSupportedDialect() {
        assertTrue(schema != null);
    }

    @Test
    void validExamplePasses() throws IOException {
        Set<ValidationMessage> messages = schema.validate(readJson(
                "examples/orchestration-v1.valid.json"
        ));
        assertTrue(messages.isEmpty(), messages.toString());
    }

    @Test
    void unknownNodeTypeIsRejected() throws IOException {
        assertInvalid("examples/orchestration-v1.invalid-unknown-node.json");
    }

    @Test
    void arbitraryUrlIsRejected() throws IOException {
        assertInvalid("examples/orchestration-v1.invalid-arbitrary-url.json");
    }

    @Test
    void retryLimitIsRejected() throws IOException {
        assertInvalid("examples/orchestration-v1.invalid-retry-limit.json");
    }

    private static void assertInvalid(String relativePath) throws IOException {
        Set<ValidationMessage> messages = schema.validate(readJson(relativePath));
        assertFalse(messages.isEmpty(), relativePath + " should fail schema validation");
    }

    private static JsonNode readJson(String relativePath) throws IOException {
        Path path = contractsDirectory.resolve(relativePath);
        assertTrue(Files.exists(path), () -> "Missing contract fixture: " + path);
        return MAPPER.readTree(path.toFile());
    }
}
