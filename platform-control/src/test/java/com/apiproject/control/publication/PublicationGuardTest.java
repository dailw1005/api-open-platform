package com.apiproject.control.publication;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicationGuardTest {

    private static final String API_ID = "api-123";
    private static final String TENANT_ID = "tenant-123";

    private final PublicationGuard guard = PublicationGuard.createDefault();

    @Test
    void acceptsPreparedProductionPublication() {
        assertDoesNotThrow(() -> guard.assertCanActivate(
                API_ID,
                TENANT_ID,
                Visibility.TENANT_PRIVATE,
                ActivationMode.PUBLISH,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.PREPARED
                )
        ));
    }

    @Test
    void acceptsRollbackToSupersededProductionPublication() {
        assertDoesNotThrow(() -> guard.assertCanActivate(
                API_ID,
                TENANT_ID,
                Visibility.TENANT_PRIVATE,
                ActivationMode.ROLLBACK,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.SUPERSEDED
                )
        ));
    }

    @Test
    void rejectsSandboxPublication() {
        assertGuardFailure(
                ActivationMode.PUBLISH,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.SANDBOX,
                        PublicationStatus.PREPARED
                ),
                "PUBLICATION_ENVIRONMENT_NOT_PROD"
        );
    }

    @Test
    void rejectsPublicationFromAnotherApi() {
        assertGuardFailure(
                ActivationMode.PUBLISH,
                publication(
                        "api-other",
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.PREPARED
                ),
                "PUBLICATION_API_MISMATCH"
        );
    }

    @Test
    void rejectsPublicationFromAnotherTenant() {
        assertGuardFailure(
                ActivationMode.PUBLISH,
                publication(
                        API_ID,
                        "tenant-other",
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.PREPARED
                ),
                "PUBLICATION_TENANT_MISMATCH"
        );
    }

    @Test
    void rejectsPublicationWithDifferentVisibility() {
        assertGuardFailure(
                ActivationMode.PUBLISH,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.PLATFORM_PUBLIC,
                        PublicationEnvironment.PROD,
                        PublicationStatus.PREPARED
                ),
                "PUBLICATION_VISIBILITY_MISMATCH"
        );
    }

    @Test
    void rejectsRevokedPublicationForPublishAndRollback() {
        PublicationSnapshot revoked = publication(
                API_ID,
                TENANT_ID,
                Visibility.TENANT_PRIVATE,
                PublicationEnvironment.PROD,
                PublicationStatus.REVOKED
        );

        assertGuardFailure(
                ActivationMode.PUBLISH,
                revoked,
                "PUBLICATION_REVOKED"
        );
        assertGuardFailure(
                ActivationMode.ROLLBACK,
                revoked,
                "PUBLICATION_REVOKED"
        );
    }

    @Test
    void rejectsPreparedPublicationForRollback() {
        assertGuardFailure(
                ActivationMode.ROLLBACK,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.PREPARED
                ),
                "PUBLICATION_STATE_NOT_ACTIVATABLE"
        );
    }

    @Test
    void rejectsSupersededPublicationForPublish() {
        assertGuardFailure(
                ActivationMode.PUBLISH,
                publication(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        PublicationEnvironment.PROD,
                        PublicationStatus.SUPERSEDED
                ),
                "PUBLICATION_STATE_NOT_ACTIVATABLE"
        );
    }

    private void assertGuardFailure(
            ActivationMode mode,
            PublicationSnapshot publication,
            String expectedCode
    ) {
        PublicationGuardException exception = assertThrows(
                PublicationGuardException.class,
                () -> guard.assertCanActivate(
                        API_ID,
                        TENANT_ID,
                        Visibility.TENANT_PRIVATE,
                        mode,
                        publication
                )
        );

        assertEquals(expectedCode, exception.code());
    }

    private PublicationSnapshot publication(
            String apiId,
            String ownerTenantId,
            Visibility visibility,
            PublicationEnvironment environment,
            PublicationStatus status
    ) {
        return new PublicationSnapshot(
                "publication-123",
                apiId,
                ownerTenantId,
                visibility,
                environment,
                status
        );
    }
}
