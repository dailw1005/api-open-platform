package com.apiproject.control.iam;

@FunctionalInterface
public interface PasswordVerifier {

    boolean matches(String rawPassword, String passwordHash);
}
