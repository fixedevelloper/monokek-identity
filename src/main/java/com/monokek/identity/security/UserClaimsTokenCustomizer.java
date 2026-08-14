package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Embeds the same claims the old {@code JwtService.generateToken(...)} did, so
 * monokek-spring and pms-modulith need near-zero changes to their claim-reading
 * code (pms's JwtAuthoritiesConverter already reads "roles"/"permissions" this way).
 * Only applies to access tokens for a user — client_credentials tokens (service-to-service
 * calls) get none of this. On a fresh password-grant login the user comes from
 * {@link UserPrincipal} already in memory; on a refresh_token grant the context's
 * principal is instead the Jackson-safe stand-in TokenIssuer stored on the
 * OAuth2Authorization (see its comment), so the user is re-fetched by id here —
 * which also means a deactivated account or a stale role stops getting fresh claims
 * at the very next refresh, not just at expiry.
 */
@Component
public class UserClaimsTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserRepository userRepository;

    public UserClaimsTokenCustomizer(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        User user = resolveUser(context);
        if (user == null) {
            return;
        }

        context.getClaims().claims(claims -> {
            claims.put("uuid", user.getUuid().toString());
            claims.put("name", user.getName());
            claims.put("roles", user.getRoles().stream().map(role -> role.getName()).toList());
            claims.put("permissions", user.getAllPermissionNames().stream().toList());
            if (user.getBranchId() != null) {
                claims.put("branch_id", user.getBranchId());
            }
        });
    }

    private User resolveUser(JwtEncodingContext context) {
        if (context.getPrincipal() instanceof UserPrincipal userPrincipal) {
            return userPrincipal.getUser();
        }
        try {
            Long userId = Long.valueOf(context.getPrincipal().getName());
            return userRepository.findById(userId).filter(User::isActive).orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
