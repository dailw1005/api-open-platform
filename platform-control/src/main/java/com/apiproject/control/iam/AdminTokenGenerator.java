package com.apiproject.control.iam;

@FunctionalInterface
public interface AdminTokenGenerator {

    String newToken();
}
