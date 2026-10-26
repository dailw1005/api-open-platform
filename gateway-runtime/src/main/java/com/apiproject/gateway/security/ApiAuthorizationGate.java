package com.apiproject.gateway.security;

@FunctionalInterface
public interface ApiAuthorizationGate {

    AuthorizedApi authorize(String appKey, String method, String path);
}
