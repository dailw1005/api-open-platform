package com.apiproject.gateway.security;

@FunctionalInterface
public interface PostAuthPolicyResolver {

    PostAuthPolicy resolve(AuthorizedApi authorizedApi);
}
