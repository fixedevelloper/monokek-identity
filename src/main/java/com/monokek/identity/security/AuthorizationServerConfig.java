package com.monokek.identity.security;

import com.monokek.identity.domain.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.cors.CorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * The OAuth2/OIDC Authorization Server itself: token endpoint (standard grants +
 * our custom password grant), JWKS, discovery. A second, ordinary resource-server
 * filter chain in {@link DefaultSecurityConfig} protects this service's own plain
 * REST endpoints (/api/admin/staff, /api/me, ...) against the tokens minted here.
 */
@Configuration
public class AuthorizationServerConfig {

    @Value("${app.identity.issuer}")
    private String issuer;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            TokenIssuer tokenIssuer,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            CorsConfigurationSource corsConfigurationSource) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        AuthenticationConverter passwordGrantConverter = new PasswordGrantAuthenticationConverter();
        PasswordGrantAuthenticationProvider passwordGrantProvider =
                new PasswordGrantAuthenticationProvider(tokenIssuer, userRepository, passwordEncoder);

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                // The POS app calls /oauth2/token directly (refresh_token grant) from the browser/
                // webview — see DefaultSecurityConfig#corsConfigurationSource's javadoc for why this
                // chain (separate from that one) needs its own .cors(...) too.
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                // No browser session/cookie involved anywhere in this service's grants
                // (custom password grant, client_credentials) — every caller is an API
                // client sending its own bearer/basic credentials, not a form post riding
                // on a session cookie, so there's no CSRF to protect against here.
                .csrf(csrf -> csrf.disable())
                .with(authorizationServerConfigurer, configurer -> configurer
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenRequestConverter(passwordGrantConverter)
                                .authenticationProvider(passwordGrantProvider))
                        .oidc(Customizer.withDefaults()))
                // No browser-based flow (authorization_code) is registered, so there's no
                // login page to redirect to on failure — default JSON error responses apply.
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Verifies/produces $2a$/$2b$/$2y$ bcrypt hashes interchangeably — unchanged
        // from monokek-spring's SecurityConfig, so existing user rows keep working.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder, UserClaimsTokenCustomizer tokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RsaKeyProperties rsaKeys) {
        RSAKey rsaKey = new RSAKey.Builder(rsaKeys.publicKey())
                .privateKey(rsaKeys.privateKey())
                .keyID(UUID.nameUUIDFromBytes(rsaKeys.publicKey().getEncoded()).toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    public RsaKeyProperties rsaKeyProperties(
            @Value("${app.identity.signing-key.private-key-pem:}") String privateKeyPem,
            @Value("${app.identity.signing-key.public-key-pem:}") String publicKeyPem) throws Exception {
        if (!privateKeyPem.isBlank() && !publicKeyPem.isBlank()) {
            return RsaKeyProperties.fromPem(privateKeyPem, publicKeyPem);
        }
        // Dev/first-boot fallback: generates an ephemeral keypair. Every token issued
        // becomes invalid on restart — see monokek-deploy for the persisted-volume PEM
        // files used in every real deployment (RSA_PRIVATE_KEY_PEM/RSA_PUBLIC_KEY_PEM).
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new RsaKeyProperties((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
    }
}
