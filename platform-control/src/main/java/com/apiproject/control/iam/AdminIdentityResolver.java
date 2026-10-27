package com.apiproject.control.iam;

import java.util.Optional;
import java.util.UUID;

public interface AdminIdentityResolver {

    Optional<AdminLoginIdentity> findByEmail(String email);

    Optional<AdminIdentity> findByUserId(UUID userId);
}
