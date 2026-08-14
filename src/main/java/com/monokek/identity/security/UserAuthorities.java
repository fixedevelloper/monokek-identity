package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.LinkedHashSet;
import java.util.Set;

/** Shared by {@link UserPrincipal} (token-issuance time) and {@link AuthenticatedUser}
 * (per-request, on this service's own resource-server chain) — both need the exact same
 * ROLE_/permission mapping, and having it in one place is what keeps them from being able
 * to silently drift apart. */
final class UserAuthorities {

    private UserAuthorities() {
    }

    static Set<GrantedAuthority> of(User user) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase())));
        user.getAllPermissionNames().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
    }
}
