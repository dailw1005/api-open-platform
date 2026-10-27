package com.apiproject.gateway.security;

@FunctionalInterface
public interface ApiTargetResolver {

    ApiTarget resolve(AuthorizedApi authorizedApi);
}
