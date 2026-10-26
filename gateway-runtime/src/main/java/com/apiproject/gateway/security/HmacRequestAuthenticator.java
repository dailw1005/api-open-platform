package com.apiproject.gateway.security;

import java.time.Instant;
import java.util.Objects;

public final class HmacRequestAuthenticator {

    private final HmacVerifier verifier;
    private final NonceReplayGuard nonceReplayGuard;

    public HmacRequestAuthenticator(
            HmacVerifier verifier,
            NonceReplayGuard nonceReplayGuard
    ) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.nonceReplayGuard = Objects.requireNonNull(
                nonceReplayGuard,
                "nonceReplayGuard"
        );
    }

    public void authenticate(
            HmacCanonicalRequest request,
            String signatureHex,
            byte[] secret,
            Instant receivedAt
    ) {
        verifier.verify(request, signatureHex, secret, receivedAt);
        nonceReplayGuard.assertUnused(request.appKey(), request.nonce());
    }
}
