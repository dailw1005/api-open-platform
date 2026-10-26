package com.apiproject.gateway.security;

import java.util.Objects;

public record PostAuthPolicy(
        TokenBucketPolicy applicationTokenBucket,
        TokenBucketPolicy apiTokenBucket,
        QuotaPolicy applicationQuota,
        QuotaPolicy apiQuota
) {

    public PostAuthPolicy {
        Objects.requireNonNull(
                applicationTokenBucket,
                "applicationTokenBucket"
        );
        Objects.requireNonNull(apiTokenBucket, "apiTokenBucket");
        Objects.requireNonNull(applicationQuota, "applicationQuota");
        Objects.requireNonNull(apiQuota, "apiQuota");
    }
}
