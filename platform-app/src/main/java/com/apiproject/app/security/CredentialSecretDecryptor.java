package com.apiproject.app.security;

@FunctionalInterface
public interface CredentialSecretDecryptor {

    /**
     * Return a new plaintext array owned by the caller. Implementations must not
     * cache the plaintext or include it in diagnostics.
     */
    byte[] decrypt(CredentialEncryptionContext context, byte[] ciphertext);
}
