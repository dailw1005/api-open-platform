package com.apiproject.control.iam;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminSessionValueTest {

    @Test
    void roleBindingRejectsUnknownRoleAndScope() {
        UUID id = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        assertThrows(
                IllegalArgumentException.class,
                () -> new SessionRoleBinding(
                        id,
                        userId,
                        UUID.randomUUID(),
                        "OWNER",
                        "GLOBAL"
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new SessionRoleBinding(
                        id,
                        userId,
                        UUID.randomUUID(),
                        "VIEWER",
                        "ROOT"
                )
        );
    }

    @Test
    void exceptionMappingsAreLimitedToKnownSafeCodes() {
        AdminAuthenticationException unavailable =
                new AdminAuthenticationException(
                        "SESSION_STORE_UNAVAILABLE",
                        true,
                        "unavailable",
                        null
                );
        assertTrue(unavailable.retryable());

        assertThrows(
                IllegalArgumentException.class,
                () -> new AdminAuthenticationException(
                        "SESSION_STORE_UNAVAILABLE",
                        false,
                        "invalid",
                        null
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new AdminAuthenticationException(
                        "UNKNOWN",
                        false,
                        "invalid",
                        null
                )
        );
    }

    @Test
    void serviceRejectsBlankIdentityMaterialAndBadTokenGenerator() {
        AdminAuthenticationService blankEmailService = service(
                Optional.empty(),
                new FixedTokenGenerator("session", "csrf")
        );
        assertCode(
                "INVALID_CREDENTIALS",
                () -> blankEmailService.login(" ", "password")
        );
        assertCode(
                "SESSION_INVALID",
                () -> blankEmailService.logout(" ")
        );

        AdminIdentity identity = adminIdentity();
        AdminAuthenticationService blankTokenService = service(
                Optional.of(new AdminLoginIdentity(
                        identity,
                        "hash",
                        false
                )),
                new FixedTokenGenerator(" ", "csrf")
        );
        assertCode(
                "INTERNAL_CONFIGURATION",
                () -> blankTokenService.login("admin@example.com", "password")
        );

        AdminAuthenticationService duplicateTokenService = service(
                Optional.of(new AdminLoginIdentity(
                        identity,
                        "hash",
                        false
                )),
                new FixedTokenGenerator("same", "same")
        );
        assertCode(
                "INTERNAL_CONFIGURATION",
                () -> duplicateTokenService.login("admin@example.com", "password")
        );
    }

    @Test
    void identityWithoutGlobalAdminIsRejected() {
        UUID userId = UUID.randomUUID();
        AdminIdentity tenantAdmin = new AdminIdentity(
                userId,
                "admin@example.com",
                "Admin",
                List.of(new SessionRoleBinding(
                        UUID.randomUUID(),
                        userId,
                        UUID.randomUUID(),
                        "PLATFORM_ADMIN",
                        "TENANT"
                ))
        );

        assertFalse(tenantAdmin.hasGlobalPlatformAdmin());
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
        return new AdminIdentity(
                userId,
                "admin@example.com",
                "Admin",
                List.of(new SessionRoleBinding(
                        UUID.randomUUID(),
                        userId,
                        UUID.randomUUID(),
                        "PLATFORM_ADMIN",
                        "GLOBAL"
                ))
        );
    }

    private AdminAuthenticationService service(
            Optional<AdminLoginIdentity> loginIdentity,
            AdminTokenGenerator tokenGenerator
    ) {
        AdminIdentityResolver resolver = new AdminIdentityResolver() {
            @Override
            public Optional<AdminLoginIdentity> findByEmail(String email) {
                return loginIdentity;
            }

            @Override
            public Optional<AdminIdentity> findByUserId(UUID userId) {
                return loginIdentity.map(AdminLoginIdentity::identity);
            }
        };
        AdminSessionStore store = new AdminSessionStore() {
            @Override
            public void create(String tokenHash, AdminSessionState state) {
            }

            @Override
            public Optional<AdminSession> find(String tokenHash) {
                return Optional.empty();
            }

            @Override
            public void revoke(String tokenHash) {
            }
        };
        return new AdminAuthenticationService(
                resolver,
                (raw, encoded) -> true,
                store,
                tokenGenerator,
                Clock.fixed(
                        Instant.parse("2026-10-27T02:00:00Z"),
                        ZoneOffset.UTC
                ),
                Duration.ofHours(8)
        );
    }

    private static final class FixedTokenGenerator
            implements AdminTokenGenerator {

        private final String[] values;
        private int index;

        private FixedTokenGenerator(String... values) {
            this.values = values.clone();
        }

        @Override
        public String newToken() {
            if (values.length == 0) {
                return "";
            }
            return values[Math.min(index++, values.length - 1)];
        }
    }
}
