package com.apiproject.app;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsKmsConfigurationTest {

    @Test
    void appliesRegionAndEndpointOverride() {
        KmsClientBuilder builder = mock(KmsClientBuilder.class);
        when(builder.overrideConfiguration(any(ClientOverrideConfiguration.class)))
                .thenReturn(builder);
        when(builder.region(any(Region.class))).thenReturn(builder);
        URI endpoint = URI.create("http://127.0.0.1:4566");

        KmsClientBuilder configured = new AwsKmsConfiguration().configure(
                builder,
                new AwsKmsProperties(
                        "us-east-1",
                        endpoint,
                        Duration.ofSeconds(2)
                )
        );

        assertEquals(builder, configured);
        verify(builder).region(Region.US_EAST_1);
        verify(builder).endpointOverride(endpoint);
    }

    @Test
    void omitsBlankRegionAndNullEndpointWhileDefaultingTimeout() {
        KmsClientBuilder builder = mock(KmsClientBuilder.class);
        when(builder.overrideConfiguration(any(ClientOverrideConfiguration.class)))
                .thenReturn(builder);

        new AwsKmsConfiguration().configure(
                builder,
                new AwsKmsProperties(" ", null, null)
        );

        verify(builder, never()).region(any(Region.class));
        verify(builder, never()).endpointOverride(any(URI.class));
    }
}
