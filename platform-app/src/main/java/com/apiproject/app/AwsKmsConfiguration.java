package com.apiproject.app;

import com.apiproject.app.security.AwsKmsCredentialSecretDecryptor;
import com.apiproject.app.security.CredentialSecretDecryptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(
        prefix = "gateway.security.kms",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
@EnableConfigurationProperties(AwsKmsProperties.class)
public class AwsKmsConfiguration {

    @Bean(destroyMethod = "close")
    KmsClient kmsClient(AwsKmsProperties properties) {
        return configure(KmsClient.builder(), properties).build();
    }

    KmsClientBuilder configure(
            KmsClientBuilder builder,
            AwsKmsProperties properties
    ) {
        builder
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .apiCallTimeout(properties.apiCallTimeout())
                        .build());
        if (properties.region() != null && !properties.region().isBlank()) {
            builder.region(Region.of(properties.region()));
        }
        if (properties.endpointOverride() != null) {
            builder.endpointOverride(properties.endpointOverride());
        }
        return builder;
    }

    @Bean
    CredentialSecretDecryptor credentialSecretDecryptor(KmsClient kmsClient) {
        return new AwsKmsCredentialSecretDecryptor(kmsClient);
    }
}
