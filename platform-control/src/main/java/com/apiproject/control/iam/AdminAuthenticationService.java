package com.apiproject.control.iam;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public final class AdminAuthenticationService {

    private final AdminIdentityResolver identityResolver;
    private final PasswordVerifier passwordVerifier;
    private final AdminSessionStore sessionStore;
    private final AdminTokenGenerator tokenGenerator;
    private final Clock clock;
    private final Duration sessionTtl;

    public AdminAuthenticationService(
            AdminIdentityResolver identityResolver,
            PasswordVerifier passwordVerifier,
            AdminSessionStore sessionStore,
            AdminTokenGenerator tokenGenerator,
            Clock clock,
            Duration sessionTtl
    ) {
        this.identityResolver = Objects.requireNonNull(
                identityResolver,
                "identityResolver"
        );
        this.passwordVerifier = Objects.requireNonNull(
                passwordVerifier,
                "passwordVerifier"
        );
        this.sessionStore = Objects.requireNonNull(
                sessionStore,
                "sessionStore"
        );
        this.tokenGenerator = Objects.requireNonNull(
                tokenGenerator,
                "tokenGenerator"
        );
        this.clock = Objects.requireNonNull(clock, "clock");
        this.sessionTtl = Objects.requireNonNull(sessionTtl, "sessionTtl");
        if (sessionTtl.isNegative() || sessionTtl.isZero()) {
            throw new IllegalArgumentException("sessionTtl must be positive");
        }
    }

    public AdminSessionTokens login(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        AdminLoginIdentity loginIdentity = identityResolver
                .findByEmail(normalizedEmail)
                .orElseThrow(this::invalidCredentials);
        if (!passwordVerifier.matches(password, loginIdentity.passwordHash())) {
            throw invalidCredentials();
        }
        if (loginIdentity.mfaEnabled()) {
            throw new AdminAuthenticationException(
                    "MFA_NOT_CONFIGURED",
                    false,
                    "MFA is required but not configured",
                    null
            );
        }
        requirePlatformAdmin(loginIdentity.identity());

        String sessionToken = validGeneratedToken();
        String csrfToken = validGeneratedToken();
        if (sessionToken.equals(csrfToken)) {
            throw internalConfiguration(
                    "Token generator returned duplicate values",
                    null
            );
        }
        Instant expiresAt = clock.instant().plus(sessionTtl);
        AdminSessionState state = new AdminSessionState(
                loginIdentity.identity().userId(),
                AdminTokenHasher.hash(csrfToken),
                expiresAt
        );
        sessionStore.create(AdminTokenHasher.hash(sessionToken), state);
        return new AdminSessionTokens(
                sessionToken,
                csrfToken,
                loginIdentity.identity(),
                expiresAt
        );
    }

    public AuthenticatedAdminSession authenticate(String sessionToken) {
        if (sessionToken == null || sessionToken.isBlank()) {
            throw sessionInvalid();
        }
        String tokenHash = AdminTokenHasher.hash(sessionToken);
        Optional<AdminSession> stored = sessionStore.find(tokenHash);
        if (stored.isEmpty()) {
            throw sessionInvalid();
        }
        AdminSession session = stored.get();
        if (!session.state().expiresAt().isAfter(clock.instant())) {
            sessionStore.revoke(tokenHash);
            throw sessionInvalid();
        }
        AdminIdentity identity = identityResolver
                .findByUserId(session.state().userId())
                .orElseThrow(this::sessionInvalid);
        requirePlatformAdmin(identity);
        return new AuthenticatedAdminSession(session.state(), identity);
    }

    public boolean csrfMatches(AdminSessionState session, String csrfToken) {
        Objects.requireNonNull(session, "session");
        if (csrfToken == null || csrfToken.isBlank()) {
            return false;
        }
        byte[] expected = session.csrfTokenHash()
                .getBytes(StandardCharsets.US_ASCII);
        byte[] actual = AdminTokenHasher.hash(csrfToken)
                .getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, actual);
    }

    public void logout(String sessionToken) {
        if (sessionToken == null || sessionToken.isBlank()) {
            throw sessionInvalid();
        }
        sessionStore.revoke(AdminTokenHasher.hash(sessionToken));
    }

    private void requirePlatformAdmin(AdminIdentity identity) {
        if (!identity.hasGlobalPlatformAdmin()) {
            throw sessionInvalid();
        }
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw invalidCredentials();
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String validGeneratedToken() {
        String token = tokenGenerator.newToken();
        if (token == null || token.isBlank()) {
            throw internalConfiguration(
                    "Token generator returned a blank value",
                    null
            );
        }
        return token;
    }

    private AdminAuthenticationException invalidCredentials() {
        return new AdminAuthenticationException(
                "INVALID_CREDENTIALS",
                false,
                "Credentials are invalid",
                null
        );
    }

    private AdminAuthenticationException sessionInvalid() {
        return new AdminAuthenticationException(
                "SESSION_INVALID",
                false,
                "Session is invalid",
                null
        );
    }

    private AdminAuthenticationException internalConfiguration(
            String message,
            Throwable cause
    ) {
        return new AdminAuthenticationException(
                "INTERNAL_CONFIGURATION",
                false,
                message,
                cause
        );
    }
}
