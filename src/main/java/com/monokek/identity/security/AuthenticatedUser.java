package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The principal bound by {@code @AuthenticationPrincipal AuthenticatedUser} in
 * StaffController/AuthController — ported unchanged from monokek-spring's identity
 * module, just no longer a UserDetails (nothing here does a password check
 * anymore: that already happened at the token endpoint).
 */
public class AuthenticatedUser {

    private final User user;

    public AuthenticatedUser(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase())));
        user.getAllPermissionNames().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
    }
}
