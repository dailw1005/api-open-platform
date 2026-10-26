package com.apiproject.app.security;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.util.Map;
import java.util.Objects;

public final class AwsKmsCredentialSecretDecryptor
        implements CredentialSecretDecryptor {

    private final KmsClient kmsClient;

    public AwsKmsCredentialSecretDecryptor(KmsClient kmsClient) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "kmsClient");
    }

    @Override
    public byte[] decrypt(CredentialEncryptionContext context, byte[] ciphertext) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(ciphertext, "ciphertext");

        SdkBytes plaintext;
        try {
            DecryptResponse response = kmsClient.decrypt(
                    DecryptRequest.builder()
                            .keyId(context.kmsKeyId())
                            .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                            .encryptionContext(Map.of(
                                    "tenantId", context.tenantId().toString(),
                                    "appId", context.appId().toString(),
                                    "credentialId", context.credentialId().toString(),
                                    "appKey", context.appKey()
                            ))
                            .build()
            );
            plaintext = response == null ? null : response.plaintext();
        } catch (KmsException exception) {
            throw new CredentialDecryptionException(
                    isRetryableStatus(exception.statusCode()),
                    "KMS decryption failed",
                    exception
            );
        } catch (SdkClientException exception) {
            throw new CredentialDecryptionException(
                    true,
                    "KMS transport failed",
                    exception
            );
        } catch (RuntimeException exception) {
            throw new CredentialDecryptionException(
                    false,
                    "KMS client failed",
                    exception
            );
        }

        if (plaintext == null || plaintext.asByteArray().length == 0) {
            throw new CredentialDecryptionException(
                    false,
                    "KMS returned an empty plaintext",
                    null
            );
        }
        return plaintext.asByteArray();
    }

    private boolean isRetryableStatus(int statusCode) {
        return statusCode == 429 || statusCode >= 500;
    }
}
