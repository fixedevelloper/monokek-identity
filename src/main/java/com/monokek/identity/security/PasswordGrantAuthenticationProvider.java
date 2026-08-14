package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Authenticates the custom password grant on the token endpoint: verifies the
 * bcrypt-hashed password (same hashes used before the extraction, Laravel-compatible),
 * then issues an access + refresh token via {@link TokenIssuer} — see
 * {@link PasswordGrantAuthenticationToken} for why this extension grant exists
 * instead of authorization_code (POS terminals/kitchen displays log in directly,
 * there's no browser to redirect).
 */
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private final TokenIssuer tokenIssuer;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public PasswordGrantAuthenticationProvider(TokenIssuer tokenIssuer, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken grant = (PasswordGrantAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(grant);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(PasswordGrantAuthenticationToken.GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        User user = userRepository.findByEmail(grant.getUsername())
                .filter(candidate -> passwordEncoder.matches(grant.getPassword(), candidate.getPassword()))
                .filter(User::isActive)
                .orElseThrow(() -> new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Les identifiants sont incorrects.", null)));

        TokenIssuer.IssuedTokens tokens = tokenIssuer.issue(user, registeredClient);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, tokens.accessToken(), tokens.refreshToken());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClient(PasswordGrantAuthenticationToken grant) {
        Object principal = grant.getPrincipal();
        if (principal instanceof OAuth2ClientAuthenticationToken clientPrincipal && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
