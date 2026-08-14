package com.monokek.identity.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.Set;

/**
 * OAuth2 extension grant carrying the {@code username}/{@code password} form
 * parameters, following the pattern documented by Spring Authorization Server for
 * custom grant types (there is no built-in "password" grant post-OAuth2.1 — POS
 * terminals/kitchen displays log in directly, so authorization_code's browser
 * redirect doesn't apply here).
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    static final AuthorizationGrantType GRANT_TYPE =
            new AuthorizationGrantType("urn:monokek:params:oauth:grant-type:password");

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            String password,
            @Nullable Set<String> scopes,
            @Nullable Map<String, Object> additionalParameters) {
        super(GRANT_TYPE, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        this.username = username;
        this.password = password;
        this.scopes = scopes == null ? Set.of() : scopes;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
