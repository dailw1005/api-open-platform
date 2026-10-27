package com.apiproject.gateway.security;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RouteTemplateExpanderTest {

    @Test
    void expandsNamedParametersAndKeepsLiteralSegments() {
        assertEquals(
                "/v1/items/item-123/history",
                RouteTemplateExpander.expand(
                        "/v1/items/{itemId}/history",
                        Map.of("itemId", "item-123")
                )
        );
    }

    @Test
    void missingOrUnsafeParameterFailsClosed() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RouteTemplateExpander.expand(
                        "/v1/items/{itemId}",
                        Map.of()
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> RouteTemplateExpander.expand(
                        "/v1/items/{itemId}",
                        Map.of("itemId", "../secret")
                )
        );
    }
}
