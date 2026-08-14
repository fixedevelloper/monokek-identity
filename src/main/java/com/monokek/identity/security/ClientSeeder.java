package com.monokek.identity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

/**
 * Registers this deployment's OAuth2 clients on first boot (idempotent — checks
 * client_id before inserting). There's no admin UI for this yet: client ids/secrets
 * come from env vars, same operational model as the old shared JWT_SECRET, except
 * now each caller has its own credential and its own scope instead of one
 * god-secret shared by every service.
 */
@Component
public class ClientSeeder implements ApplicationRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final String posClientId;
    private final String posClientSecret;
    private final String springServiceClientId;
    private final String springServiceClientSecret;
    private final String internalClientId;
    private final String internalClientSecret;

    public ClientSeeder(
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.identity.clients.pos.client-id}") String posClientId,
            @Value("${app.identity.clients.pos.client-secret}") String posClientSecret,
            @Value("${app.identity.clients.monokek-spring.client-id}") String springServiceClientId,
            @Value("${app.identity.clients.monokek-spring.client-secret}") String springServiceClientSecret,
            @Value("${app.identity.clients.internal.client-id}") String internalClientId,
            @Value("${app.identity.clients.internal.client-secret}") String internalClientSecret) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.posClientId = posClientId;
        this.posClientSecret = posClientSecret;
        this.springServiceClientId = springServiceClientId;
        this.springServiceClientSecret = springServiceClientSecret;
        this.internalClientId = internalClientId;
        this.internalClientSecret = internalClientSecret;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedIfMissing(posClientId, this::posClient);
        seedIfMissing(springServiceClientId, () -> serviceClient(springServiceClientId, springServiceClientSecret, "internal.users.read"));
        seedIfMissing(internalClientId, () -> serviceClient(internalClientId, internalClientSecret, "internal.activity-log.write"));
    }

    private void seedIfMissing(String clientId, java.util.function.Supplier<RegisteredClient> factory) {
        if (registeredClientRepository.findByClientId(clientId) == null) {
            registeredClientRepository.save(factory.get());
        }
    }

    /**
     * POS terminals / kitchen displays: our custom password grant + refresh_token. Uses
     * CLIENT_SECRET_BASIC rather than a truly public (secret-less) client — Spring
     * Authorization Server's built-in secret-less client authentication
     * (PublicClientAuthenticationConverter) only activates for PKCE authorization_code
     * requests, not extension grants like ours. The secret here identifies "this is a
     * genuine monokek-pos build" (baked into the Tauri app), not an end-user credential —
     * the real authentication factor is still the user's own email+password, checked in
     * PasswordGrantAuthenticationProvider.
     */
    private RegisteredClient posClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(posClientId)
                .clientSecret(passwordEncoder.encode(posClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).requireProofKey(false).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build())
                .build();
    }

    /** Server-to-server: client_credentials, one scope per caller/purpose (least privilege). */
    private RegisteredClient serviceClient(String clientId, String clientSecret, String scope) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(scope)
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).build())
                .build();
    }
}
