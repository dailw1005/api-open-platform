package com.apiproject.app;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties("gateway.security.pre-auth-rate-limit")
public record PreAuthRateLimitProperties(
        int requests,
        Duration window
) {

    public PreAuthRateLimitProperties {
        requests = requests <= 0 ? 120 : requests;
        window = window == null ? Duration.ofMinutes(1) : window;
    }
}
