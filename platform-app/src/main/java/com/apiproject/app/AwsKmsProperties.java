package com.apiproject.app;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;

@ConfigurationProperties("gateway.security.kms")
public record AwsKmsProperties(
        String region,
        URI endpointOverride,
        Duration apiCallTimeout
) {

    public AwsKmsProperties {
        apiCallTimeout = apiCallTimeout == null
                ? Duration.ofSeconds(3)
                : apiCallTimeout;
    }
}
