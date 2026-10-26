package com.apiproject.app.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsKmsCredentialSecretDecryptorTest {

    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final UUID APP_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();
    private static final String APP_KEY = "ak_kms_test_1234567890abcdef";
    private static final String KMS_KEY_ID = "alias/api-open-platform";
    private static final byte[] CIPHERTEXT = new byte[]{1, 2, 3, 4, 5};
    private static final byte[] PLAINTEXT = new byte[32];

    private KmsClient kmsClient;
    private AwsKmsCredentialSecretDecryptor decryptor;

    @BeforeEach
    void setUp() {
        kmsClient = mock(KmsClient.class);
        decryptor = new AwsKmsCredentialSecretDecryptor(kmsClient);
    }

    @Test
    void decryptsWithBoundEncryptionContext() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenReturn(
                DecryptResponse.builder()
                        .plaintext(SdkBytes.fromByteArray(PLAINTEXT))
                        .build()
        );

        byte[] result = decryptor.decrypt(context(), CIPHERTEXT);

        assertArrayEquals(PLAINTEXT, result);
        ArgumentCaptor<DecryptRequest> request =
                ArgumentCaptor.forClass(DecryptRequest.class);
        verify(kmsClient).decrypt(request.capture());
        assertEquals(KMS_KEY_ID, request.getValue().keyId());
        assertArrayEquals(CIPHERTEXT, request.getValue().ciphertextBlob().asByteArray());
        assertEquals(
                Map.of(
                        "tenantId", TENANT_ID.toString(),
                        "appId", APP_ID.toString(),
                        "credentialId", CREDENTIAL_ID.toString(),
                        "appKey", APP_KEY
                ),
                request.getValue().encryptionContext()
        );
    }

    @Test
    void retryableServiceFailureIsClassifiedAsRetryable() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenThrow(
                KmsException.builder()
                        .message("service unavailable")
                        .statusCode(503)
                        .build()
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertTrue(exception.retryable());
        assertFalse(exception.getMessage().contains("service unavailable"));
    }

    @Test
    void throttlingFailureIsRetryable() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenThrow(
                KmsException.builder()
                        .message("throttled")
                        .statusCode(429)
                        .build()
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertTrue(exception.retryable());
    }

    @Test
    void clientTransportFailureIsRetryable() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenThrow(
                SdkClientException.create("network timeout")
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertTrue(exception.retryable());
        assertFalse(exception.getMessage().contains("network timeout"));
    }

    @Test
    void invalidCiphertextIsNonRetryable() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenThrow(
                InvalidCiphertextException.builder()
                        .message("invalid ciphertext")
                        .statusCode(400)
                        .build()
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertFalse(exception.retryable());
        assertFalse(exception.getMessage().contains("invalid ciphertext"));
    }

    @Test
    void emptyPlaintextFailsClosed() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenReturn(
                DecryptResponse.builder()
                        .plaintext(SdkBytes.fromByteArray(new byte[0]))
                        .build()
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertFalse(exception.retryable());
    }

    @Test
    void nullResponseFailsClosed() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenReturn(null);

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertFalse(exception.retryable());
    }

    @Test
    void unexpectedRuntimeFailureIsNonRetryable() {
        when(kmsClient.decrypt(any(DecryptRequest.class))).thenThrow(
                new IllegalStateException("unexpected")
        );

        CredentialDecryptionException exception = assertThrows(
                CredentialDecryptionException.class,
                () -> decryptor.decrypt(context(), CIPHERTEXT)
        );

        assertFalse(exception.retryable());
        assertFalse(exception.getMessage().contains("unexpected"));
    }

    private CredentialEncryptionContext context() {
        return new CredentialEncryptionContext(
                TENANT_ID,
                APP_ID,
                CREDENTIAL_ID,
                APP_KEY,
                KMS_KEY_ID
        );
    }
}
