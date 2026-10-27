package com.apiproject.gateway.security;

@FunctionalInterface
public interface UpstreamClient {

    UpstreamResponse execute(UpstreamRequest request);
}
