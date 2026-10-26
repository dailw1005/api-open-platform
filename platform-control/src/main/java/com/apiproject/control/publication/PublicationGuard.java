package com.apiproject.control.publication;

import java.util.Objects;

public final class PublicationGuard {

    private PublicationGuard() {
    }

    public static PublicationGuard createDefault() {
        return new PublicationGuard();
    }

    public void assertCanActivate(
            String expectedApiId,
            String expectedOwnerTenantId,
            Visibility expectedVisibility,
            ActivationMode mode,
            PublicationSnapshot publication
    ) {
        Objects.requireNonNull(expectedApiId, "expectedApiId");
        Objects.requireNonNull(expectedOwnerTenantId, "expectedOwnerTenantId");
        Objects.requireNonNull(expectedVisibility, "expectedVisibility");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(publication, "publication");

        if (publication.environment() != PublicationEnvironment.PROD) {
            throw failure(
                    "PUBLICATION_ENVIRONMENT_NOT_PROD",
                    "Only production publications can become the active pointer"
            );
        }
        if (!expectedApiId.equals(publication.apiId())) {
            throw failure(
                    "PUBLICATION_API_MISMATCH",
                    "Publication belongs to a different API"
            );
        }
        if (!expectedOwnerTenantId.equals(publication.ownerTenantId())) {
            throw failure(
                    "PUBLICATION_TENANT_MISMATCH",
                    "Publication belongs to a different tenant"
            );
        }
        if (expectedVisibility != publication.visibility()) {
            throw failure(
                    "PUBLICATION_VISIBILITY_MISMATCH",
                    "Publication visibility differs from the API definition"
            );
        }
        if (publication.status() == PublicationStatus.REVOKED) {
            throw failure(
                    "PUBLICATION_REVOKED",
                    "Revoked publications cannot be activated"
            );
        }
        if (!isActivatable(mode, publication.status())) {
            throw failure(
                    "PUBLICATION_STATE_NOT_ACTIVATABLE",
                    "Publication state is not valid for activation mode " + mode
            );
        }
    }

    private boolean isActivatable(
            ActivationMode mode,
            PublicationStatus status
    ) {
        return switch (mode) {
            case PUBLISH -> status == PublicationStatus.PREPARED;
            case ROLLBACK -> status == PublicationStatus.ACTIVE
                    || status == PublicationStatus.SUPERSEDED;
        };
    }

    private PublicationGuardException failure(String code, String message) {
        return new PublicationGuardException(code, message);
    }
}
