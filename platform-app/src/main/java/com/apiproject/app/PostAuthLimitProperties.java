package com.apiproject.app;

import com.apiproject.gateway.security.PostAuthPolicy;
import com.apiproject.gateway.security.QuotaPolicy;
import com.apiproject.gateway.security.TokenBucketPolicy;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Objects;

@ConfigurationProperties("gateway.security.post-auth-limit")
public record PostAuthLimitProperties(
        TokenBucket applicationRate,
        TokenBucket apiRate,
        Quota applicationQuota,
        Quota apiQuota
) {

    private static final TokenBucket DEFAULT_APPLICATION_RATE =
            new TokenBucket(600, Duration.ofMinutes(1), 120);
    private static final TokenBucket DEFAULT_API_RATE =
            new TokenBucket(300, Duration.ofMinutes(1), 60);
    private static final Quota DEFAULT_APPLICATION_QUOTA =
            new Quota(100_000, 2_000_000);
    private static final Quota DEFAULT_API_QUOTA =
            new Quota(50_000, 1_000_000);

    public PostAuthLimitProperties {
        applicationRate = applicationRate == null
                ? DEFAULT_APPLICATION_RATE
                : applicationRate;
        apiRate = apiRate == null ? DEFAULT_API_RATE : apiRate;
        applicationQuota = applicationQuota == null
                ? DEFAULT_APPLICATION_QUOTA
                : applicationQuota;
        apiQuota = apiQuota == null ? DEFAULT_API_QUOTA : apiQuota;
    }

    public PostAuthPolicy defaultPolicy() {
        return new PostAuthPolicy(
                applicationRate.toPolicy(),
                apiRate.toPolicy(),
                applicationQuota.toPolicy(),
                apiQuota.toPolicy()
        );
    }

    public record TokenBucket(
            long requests,
            Duration window,
            int burst
    ) {

        public TokenBucket {
            if (requests <= 0) {
                throw new IllegalArgumentException("requests must be positive");
            }
            Objects.requireNonNull(window, "window");
            if (window.isNegative() || window.toMillis() <= 0) {
                throw new IllegalArgumentException(
                        "window must be at least one millisecond"
                );
            }
            if (burst <= 0) {
                throw new IllegalArgumentException("burst must be positive");
            }
        }

        TokenBucketPolicy toPolicy() {
            return new TokenBucketPolicy(requests, window, burst);
        }
    }

    public record Quota(
            long daily,
            long monthly
    ) {

        public Quota {
            if (daily <= 0) {
                throw new IllegalArgumentException("daily must be positive");
            }
            if (monthly <= 0) {
                throw new IllegalArgumentException("monthly must be positive");
            }
        }

        QuotaPolicy toPolicy() {
            return new QuotaPolicy(daily, monthly);
        }
    }
}
