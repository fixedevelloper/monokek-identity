package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Embeds the same claims the old {@code JwtService.generateToken(...)} did, so
 * monokek-spring and pms-modulith need near-zero changes to their claim-reading
 * code (pms's JwtAuthoritiesConverter already reads "roles"/"permissions" this way,
 * and both use the presence of a "roles" claim to distinguish a user token from a
 * client_credentials one). Only applies to access tokens for a user —
 * client_credentials tokens (service-to-service calls) get none of this. On a fresh
 * password-grant login the user comes from {@link UserPrincipal} already in memory;
 * on a refresh_token grant the context's principal is instead the Jackson-safe
 * stand-in TokenIssuer stored on the OAuth2Authorization (see its comment), so the
 * user is re-fetched by id here — which also means a deactivated account or a stale
 * role stops getting fresh claims at the very next refresh, not just at expiry.
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

        if (context.getPrincipal() instanceof UserPrincipal userPrincipal) {
            applyClaims(context, userPrincipal.getUser());
            return;
        }

        Long userId = asUserId(context.getPrincipal().getName());
        if (userId == null) {
            // Not a user-shaped principal name at all — a client_credentials caller
            // (e.g. "monokek-spring-service"), nothing to add.
            return;
        }

        User user = userRepository.findById(userId).filter(User::isActive).orElse(null);
        if (user == null) {
            // A refresh_token for a user deactivated/deleted since it was issued. Silently
            // skipping claims here (the old behavior) would mint a token carrying no "roles"
            // claim at all — every downstream resource server would then misclassify it as a
            // client_credentials service token instead of rejecting it outright.
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Ce compte n'est plus actif.", null));
        }
        applyClaims(context, user);
    }

    private void applyClaims(JwtEncodingContext context, User user) {
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

    private static Long asUserId(String principalName) {
        try {
            return Long.valueOf(principalName);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
