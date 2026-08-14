package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

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
        return UserAuthorities.of(user);
    }
}
