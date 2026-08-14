package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * The token endpoint's principal for the custom password grant, carrying the
 * authenticated {@link User} through to the JWT claims customizer. {@code getName()}
 * (the OAuth2 "principal_name") is the user id, matching the {@code sub} claim
 * every resource server (monokek-spring, pms-modulith) already expects.
 */
public class UserPrincipal extends AbstractAuthenticationToken {

    private final User user;

    public UserPrincipal(User user) {
        super(UserAuthorities.of(user));
        this.user = user;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    @Override
    public String getName() {
        return user.getId().toString();
    }

    public User getUser() {
        return user;
    }
}
