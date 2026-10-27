package com.apiproject.control.iam;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminAuthenticationServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-27T02:00:00Z");
    private static final Duration TTL = Duration.ofHours(8);
    private static final String SESSION_TOKEN =
            "session-token-abcdefghijklmnopqrstuvwxyz0123456789";
    private static final String CSRF_TOKEN =
            "csrf-token-abcdefghijklmnopqrstuvwxyz0123456789";

    private AdminIdentity identity;
    private RecordingSessionStore store;
    private StubIdentityResolver resolver;
    private AdminAuthenticationService service;

    @BeforeEach
    void setUp() {
        identity = adminIdentity();
        store = new RecordingSessionStore();
        resolver = new StubIdentityResolver(identity);
        service = new AdminAuthenticationService(
                resolver,
                (raw, encoded) -> "correct-password".equals(raw)
                        && "password-hash".equals(encoded),
                store,
                new QueueTokenGenerator(SESSION_TOKEN, CSRF_TOKEN),
                Clock.fixed(NOW, ZoneOffset.UTC),
                TTL
        );
    }

    @Test
    void successfulLoginIssuesRawTokensAndStoresOnlyHashes() {
        AdminSessionTokens tokens = service.login(
                "  ADMIN@example.com ",
                "correct-password"
        );

        assertEquals(identity, tokens.identity());
        assertEquals(SESSION_TOKEN, tokens.sessionToken());
        assertEquals(CSRF_TOKEN, tokens.csrfToken());
        assertEquals(NOW.plus(TTL), tokens.expiresAt());
        assertEquals("admin@example.com", resolver.lastEmail);
        assertEquals(
                AdminTokenHasher.hash(SESSION_TOKEN),
                store.createdTokenHash
        );
        assertEquals(
                AdminTokenHasher.hash(CSRF_TOKEN),
                store.createdState.csrfTokenHash()
        );
        assertEquals(identity.userId(), store.createdState.userId());
        assertEquals(NOW.plus(TTL), store.createdState.expiresAt());
    }

    @Test
    void unknownUserWrongPasswordAndMfaFailClosed() {
        resolver.loginIdentity = Optional.empty();
        assertCode(
                "INVALID_CREDENTIALS",
                () -> service.login("missing@example.com", "wrong-password")
        );

        resolver.loginIdentity = Optional.of(loginIdentity(false));
        assertCode(
                "INVALID_CREDENTIALS",
                () -> service.login("admin@example.com", "wrong-password")
        );

        resolver.loginIdentity = Optional.of(loginIdentity(true));
        assertCode(
                "MFA_NOT_CONFIGURED",
                () -> service.login("admin@example.com", "correct-password")
        );
        assertEquals(null, store.createdState);
    }

    @Test
    void authenticateRequiresActiveAdminAndUnexpiredSession() {
        store.session = Optional.of(session(NOW.plusSeconds(60)));

        AuthenticatedAdminSession authenticated =
                service.authenticate(SESSION_TOKEN);

        assertSame(store.session.orElseThrow().state(), authenticated.session());
        assertEquals(identity, authenticated.identity());

        store.session = Optional.of(session(NOW.minusSeconds(1)));
        assertCode(
                "SESSION_INVALID",
                () -> service.authenticate(SESSION_TOKEN)
        );
        assertEquals(
                AdminTokenHasher.hash(SESSION_TOKEN),
                store.revokedTokenHash
        );

        store.session = Optional.of(session(NOW.plusSeconds(60)));
        resolver.identity = Optional.of(identityWithoutAdminRole());
        assertCode(
                "SESSION_INVALID",
                () -> service.authenticate(SESSION_TOKEN)
        );
    }

    @Test
    void missingSessionAndStoreFailureFailClosed() {
        store.session = Optional.empty();
        assertCode(
                "SESSION_INVALID",
                () -> service.authenticate(SESSION_TOKEN)
        );

        store.failure = new AdminAuthenticationException(
                "SESSION_STORE_UNAVAILABLE",
                true,
                "store down",
                null
        );
        assertCode(
                "SESSION_STORE_UNAVAILABLE",
                () -> service.authenticate(SESSION_TOKEN)
        );
    }

    @Test
    void csrfValidationUsesStoredHash() {
        AdminSessionState state = session(NOW.plusSeconds(60)).state();

        assertTrue(service.csrfMatches(state, CSRF_TOKEN));
        assertFalse(service.csrfMatches(state, "wrong-token"));
        assertFalse(service.csrfMatches(state, null));
    }

    @Test
    void logoutRevokesTheHashedSessionKey() {
        service.logout(SESSION_TOKEN);

        assertEquals(AdminTokenHasher.hash(SESSION_TOKEN), store.revokedTokenHash);
    }

    @Test
    void constructorRequiresPositiveTtl() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AdminAuthenticationService(
                        resolver,
                        (raw, encoded) -> true,
                        store,
                        new QueueTokenGenerator(SESSION_TOKEN, CSRF_TOKEN),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        Duration.ZERO
                )
        );
    }

    private void assertCode(
            String code,
            org.junit.jupiter.api.function.Executable executable
    ) {
        AdminAuthenticationException exception = assertThrows(
                AdminAuthenticationException.class,
                executable
        );
        assertEquals(code, exception.code());
    }

    private AdminIdentity adminIdentity() {
        UUID userId = UUID.randomUUID();
        SessionRoleBinding admin = new SessionRoleBinding(
                UUID.randomUUID(),
                userId,
                UUID.randomUUID(),
                "PLATFORM_ADMIN",
                "GLOBAL"
        );
        return new AdminIdentity(
                userId,
                "admin@example.com",
                "Admin",
                List.of(admin)
        );
    }

    private AdminIdentity identityWithoutAdminRole() {
        return new AdminIdentity(
                identity.userId(),
                identity.email(),
                identity.displayName(),
                List.of(new SessionRoleBinding(
                        UUID.randomUUID(),
                        identity.userId(),
                        UUID.randomUUID(),
                        "VIEWER",
                        "TENANT"
                ))
        );
    }

    private AdminLoginIdentity loginIdentity(boolean mfaEnabled) {
        return new AdminLoginIdentity(
                identity,
                "password-hash",
                mfaEnabled
        );
    }

    private AdminSession session(Instant expiresAt) {
        AdminSessionState state = new AdminSessionState(
                identity.userId(),
                AdminTokenHasher.hash(CSRF_TOKEN),
                expiresAt
        );
        return new AdminSession(
                AdminTokenHasher.hash(SESSION_TOKEN),
                state
        );
    }

    private static final class QueueTokenGenerator
            implements AdminTokenGenerator {

        private final Queue<String> tokens = new ArrayDeque<>();

        private QueueTokenGenerator(String... values) {
            tokens.addAll(List.of(values));
        }

        @Override
        public String newToken() {
            return tokens.remove();
        }
    }

    private static final class StubIdentityResolver
            implements AdminIdentityResolver {

        private Optional<AdminLoginIdentity> loginIdentity;
        private Optional<AdminIdentity> identity;
        private String lastEmail;

        private StubIdentityResolver(AdminIdentity admin) {
            this.loginIdentity = Optional.of(
                    new AdminLoginIdentity(admin, "password-hash", false)
            );
            this.identity = Optional.of(admin);
        }

        @Override
        public Optional<AdminLoginIdentity> findByEmail(String email) {
            lastEmail = email;
            return loginIdentity;
        }

        @Override
        public Optional<AdminIdentity> findByUserId(UUID userId) {
            return identity;
        }
    }

    private static final class RecordingSessionStore
            implements AdminSessionStore {

        private String createdTokenHash;
        private AdminSessionState createdState;
        private Optional<AdminSession> session = Optional.empty();
        private String revokedTokenHash;
        private RuntimeException failure;

        @Override
        public void create(String tokenHash, AdminSessionState state) {
            if (failure != null) {
                throw failure;
            }
            createdTokenHash = tokenHash;
            createdState = state;
        }

        @Override
        public Optional<AdminSession> find(String tokenHash) {
            if (failure != null) {
                throw failure;
            }
            return session;
        }

        @Override
        public void revoke(String tokenHash) {
            if (failure != null) {
                throw failure;
            }
            revokedTokenHash = tokenHash;
        }
    }
}
