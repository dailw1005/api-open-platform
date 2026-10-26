package com.apiproject.orchestration;

import java.util.Optional;

@FunctionalInterface
public interface ApiMetadataResolver {
    Optional<ApiMetadata> resolve(String apiRef);
}
