package com.apiproject.app;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.Objects;

@ConfigurationProperties("gateway.security")
public record GatewaySecurityProperties(URI redisUri) {

    public GatewaySecurityProperties {
        redisUri = Objects.requireNonNullElse(
                redisUri,
                URI.create("redis://127.0.0.1:6379")
        );
    }
}
