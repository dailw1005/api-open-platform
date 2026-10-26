package com.apiproject.gateway.security;

import java.util.Optional;

@FunctionalInterface
public interface ActiveCredentialResolver {

    /**
     * Return a defensive copy of the active secret or empty when the AppKey is
     * unknown, disabled, expired, or revoked. The caller wipes the returned array.
     */
    Optional<byte[]> resolveActiveSecret(String appKey);
}
