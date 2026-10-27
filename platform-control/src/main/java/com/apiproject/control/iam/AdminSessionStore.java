package com.apiproject.control.iam;

import java.util.Optional;

public interface AdminSessionStore {

    void create(String tokenHash, AdminSessionState state);

    Optional<AdminSession> find(String tokenHash);

    void revoke(String tokenHash);
}
