package com.apiproject.app;

import com.apiproject.app.security.CredentialSecretDecryptor;
import com.apiproject.app.security.GatewayDatabaseRoleVerifier;
import com.apiproject.app.security.JdbcApiAuthorizationGate;
import com.apiproject.app.security.JdbcActiveCredentialResolver;
import com.apiproject.gateway.security.ActiveCredentialResolver;
import com.apiproject.gateway.security.ApiAuthorizationGate;
import com.apiproject.gateway.security.HmacAuthenticationFilter;
import com.apiproject.gateway.security.HmacRequestAuthenticator;
import com.apiproject.gateway.security.HmacVerifier;
import com.apiproject.gateway.security.JedisNonceReplayStore;
import com.apiproject.gateway.security.NonceReplayGuard;
import com.apiproject.gateway.security.NonceReplayStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import redis.clients.jedis.JedisPooled;

import javax.sql.DataSource;
import java.time.Clock;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(GatewaySecurityProperties.class)
public class RuntimeSecurityConfiguration {

    @Bean(destroyMethod = "close")
    JedisPooled gatewayJedis(GatewaySecurityProperties properties) {
        return new JedisPooled(properties.redisUri());
    }

    @Bean
    NonceReplayStore nonceReplayStore(JedisPooled jedis) {
        return new JedisNonceReplayStore(jedis);
    }

    @Bean
    HmacRequestAuthenticator hmacRequestAuthenticator(NonceReplayStore store) {
        return new HmacRequestAuthenticator(
                HmacVerifier.createDefault(),
                NonceReplayGuard.createDefault(store)
        );
    }

    @Bean
    ActiveCredentialResolver activeCredentialResolver(
            DataSource dataSource,
            CredentialSecretDecryptor decryptor
    ) {
        return new JdbcActiveCredentialResolver(dataSource, decryptor);
    }

    @Bean
    ApiAuthorizationGate apiAuthorizationGate(DataSource dataSource) {
        return new JdbcApiAuthorizationGate(dataSource);
    }

    @Bean
    GatewayDatabaseRoleVerifier gatewayDatabaseRoleVerifier(DataSource dataSource) {
        return new GatewayDatabaseRoleVerifier(dataSource);
    }

    @Bean
    @ConditionalOnProperty(
            prefix = "gateway.security.database-role-verification",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    ApplicationRunner gatewayDatabaseRoleVerificationRunner(
            GatewayDatabaseRoleVerifier verifier
    ) {
        return arguments -> verifier.verify();
    }

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    Clock gatewayClock() {
        return Clock.systemUTC();
    }

    @Bean
    FilterRegistrationBean<HmacAuthenticationFilter> hmacAuthenticationFilter(
            ActiveCredentialResolver credentialResolver,
            HmacRequestAuthenticator authenticator,
            ObjectMapper objectMapper,
            Clock clock,
            ApiAuthorizationGate authorizationGate
    ) {
        FilterRegistrationBean<HmacAuthenticationFilter> registration =
                new FilterRegistrationBean<>();
        registration.setName("hmacAuthenticationFilter");
        registration.setFilter(new HmacAuthenticationFilter(
                credentialResolver,
                authenticator,
                objectMapper,
                clock,
                authorizationGate
        ));
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        return registration;
    }
}
