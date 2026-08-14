package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Shared token-issuing logic behind both the OAuth2 password grant
 * ({@link PasswordGrantAuthenticationProvider}, for future/third-party clients) and
 * {@code /api/login} ({@code AuthController}, kept for the existing frontend so it
 * doesn't have to speak raw OAuth2 form-encoding). Manages its own
 * {@link AuthorizationServerContext} instead of relying on the one
 * {@code AuthorizationServerContextFilter} sets — that filter only runs for requests
 * matched by the AS's own endpoints, not for {@code /api/login}.
 */
@Component
public class TokenIssuer {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final AuthorizationServerSettings authorizationServerSettings;

    public TokenIssuer(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    public record IssuedTokens(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
    }

    public IssuedTokens issue(User user, RegisteredClient registeredClient) {
        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return authorizationServerSettings.getIssuer();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        });
        try {
            return doIssue(user, registeredClient);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    private IssuedTokens doIssue(User user, RegisteredClient registeredClient) {
        UserPrincipal userPrincipal = new UserPrincipal(user);
        Set<String> authorizedScopes = registeredClient.getScopes();

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE);

        // OAuth2RefreshTokenAuthenticationProvider rebuilds the principal for the *new*
        // access token by deserializing this attribute (Jackson, via JdbcOAuth2AuthorizationService)
        // — the refresh_token call is only authenticated as the client, there's no live user
        // Authentication to reuse the way there is on the original password-grant request.
        // UserPrincipal itself isn't Jackson-safe (Spring Security's allowlist has no mixin
        // for it, and it carries the full JPA User entity) — store a bare, allowlisted
        // UsernamePasswordAuthenticationToken(userId) instead; UserClaimsTokenCustomizer
        // re-fetches the User from the DB by that id when it sees this shape, which as a
        // side effect re-checks isActive()/roles/permissions on every refresh instead of
        // trusting a potentially-stale in-memory snapshot.
        Authentication storedPrincipal = new UsernamePasswordAuthenticationToken(
                userPrincipal.getName(), null, userPrincipal.getAuthorities());

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userPrincipal.getName())
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(java.security.Principal.class.getName(), storedPrincipal);

        OAuth2TokenContext accessTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes);
        authorizationBuilder.accessToken(accessToken);

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        authorizationService.save(authorizationBuilder.build());
        return new IssuedTokens(accessToken, refreshToken);
    }
}
