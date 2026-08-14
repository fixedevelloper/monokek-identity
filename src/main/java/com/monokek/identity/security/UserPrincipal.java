package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The token endpoint's principal for the custom password grant, carrying the
 * authenticated {@link User} through to the JWT claims customizer. {@code getName()}
 * (the OAuth2 "principal_name") is the user id, matching the {@code sub} claim
 * every resource server (monokek-spring, pms-modulith) already expects.
 */
public class UserPrincipal extends AbstractAuthenticationToken {

    private final User user;

    public UserPrincipal(User user) {
        super(authorities(user));
        this.user = user;
        setAuthenticated(true);
    }

    private static Set<GrantedAuthority> authorities(User user) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase())));
        user.getAllPermissionNames().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
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
