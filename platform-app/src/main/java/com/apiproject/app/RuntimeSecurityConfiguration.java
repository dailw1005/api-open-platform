package com.apiproject.app;

import com.apiproject.app.security.CredentialSecretDecryptor;
import com.apiproject.app.security.GatewayDatabaseRoleVerifier;
import com.apiproject.app.security.JdbcApiAuthorizationGate;
import com.apiproject.app.security.JdbcActiveCredentialResolver;
import com.apiproject.app.security.JdbcPostAuthPolicyResolver;
import com.apiproject.app.security.JdbcApiTargetResolver;
import com.apiproject.gateway.security.ActiveCredentialResolver;
import com.apiproject.gateway.security.ApiAuthorizationGate;
import com.apiproject.gateway.security.ApiProxyFilter;
import com.apiproject.gateway.security.ApiTargetResolver;
import com.apiproject.gateway.security.HmacAuthenticationFilter;
import com.apiproject.gateway.security.HmacRequestAuthenticator;
import com.apiproject.gateway.security.HmacVerifier;
import com.apiproject.gateway.security.JedisNonceReplayStore;
import com.apiproject.gateway.security.JdkUpstreamClient;
import com.apiproject.gateway.security.NonceReplayGuard;
import com.apiproject.gateway.security.NonceReplayStore;
import com.apiproject.gateway.security.PolicyPostAuthLimitGate;
import com.apiproject.gateway.security.PostAuthLimitGate;
import com.apiproject.gateway.security.PostAuthPolicyResolver;
import com.apiproject.gateway.security.PostAuthRateLimiter;
import com.apiproject.gateway.security.PreAuthRateLimiter;
import com.apiproject.gateway.security.RedisPostAuthRateLimiter;
import com.apiproject.gateway.security.RedisPreAuthRateLimiter;
import com.apiproject.gateway.security.UpstreamClient;
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
@EnableConfigurationProperties({
        GatewaySecurityProperties.class,
        PreAuthRateLimitProperties.class,
        PostAuthLimitProperties.class
})
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
    PreAuthRateLimiter preAuthRateLimiter(
            JedisPooled jedis,
            PreAuthRateLimitProperties properties,
            Clock clock
    ) {
        return new RedisPreAuthRateLimiter(
                jedis,
                properties.requests(),
                properties.window(),
                clock
        );
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
    ApiAuthorizationGate apiAuthorizationGate(
            DataSource dataSource,
            ObjectMapper objectMapper
    ) {
        return new JdbcApiAuthorizationGate(dataSource, objectMapper);
    }

    @Bean
    ApiTargetResolver apiTargetResolver(DataSource dataSource) {
        return new JdbcApiTargetResolver(dataSource);
    }

    @Bean
    UpstreamClient upstreamClient() {
        return new JdkUpstreamClient();
    }

    @Bean
    PostAuthPolicyResolver postAuthPolicyResolver(
            DataSource dataSource,
            PostAuthLimitProperties properties
    ) {
        return new JdbcPostAuthPolicyResolver(dataSource, properties);
    }

    @Bean
    PostAuthRateLimiter postAuthRateLimiter(JedisPooled jedis) {
        return new RedisPostAuthRateLimiter(jedis);
    }

    @Bean
    PostAuthLimitGate postAuthLimitGate(
            PostAuthPolicyResolver policyResolver,
            PostAuthRateLimiter rateLimiter
    ) {
        return new PolicyPostAuthLimitGate(policyResolver, rateLimiter);
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
            ApiAuthorizationGate authorizationGate,
            PreAuthRateLimiter preAuthRateLimiter,
            PostAuthLimitGate postAuthLimitGate
    ) {
        FilterRegistrationBean<HmacAuthenticationFilter> registration =
                new FilterRegistrationBean<>();
        registration.setName("hmacAuthenticationFilter");
        registration.setFilter(new HmacAuthenticationFilter(
                credentialResolver,
                authenticator,
                objectMapper,
                clock,
                authorizationGate,
                preAuthRateLimiter,
                postAuthLimitGate
        ));
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        return registration;
    }

    @Bean
    FilterRegistrationBean<ApiProxyFilter> apiProxyFilter(
            ApiTargetResolver targetResolver,
            UpstreamClient upstreamClient,
            ObjectMapper objectMapper
    ) {
        FilterRegistrationBean<ApiProxyFilter> registration =
                new FilterRegistrationBean<>();
        registration.setName("apiProxyFilter");
        registration.setFilter(new ApiProxyFilter(
                targetResolver,
                upstreamClient,
                objectMapper
        ));
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 30);
        return registration;
    }
}
