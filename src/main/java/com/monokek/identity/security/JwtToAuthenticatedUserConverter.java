package com.monokek.identity.security;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

/**
 * Distinguishes two kinds of tokens this service issues and validates for its own
 * REST endpoints: user tokens from the password grant (carry a "roles" claim — see
 * UserClaimsTokenCustomizer) and client_credentials service tokens (scope-based
 * authorities only, no user to load). Re-reading the user's roles/permissions from
 * the DB on every request — rather than trusting the JWT's claims — means a
 * permission change or account deactivation takes effect immediately, not only
 * once the access token expires.
 */
@Component
public class JwtToAuthenticatedUserConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserRepository userRepository;
    private final JwtGrantedAuthoritiesConverter scopeAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public JwtToAuthenticatedUserConverter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (jwt.getClaimAsStringList("roles") == null) {
            return new JwtAuthenticationToken(jwt, scopeAuthoritiesConverter.convert(jwt));
        }

        Long userId;
        try {
            userId = Long.valueOf(jwt.getSubject());
        } catch (NumberFormatException e) {
            throw new BadCredentialsException("Le claim 'sub' du token n'est pas un identifiant utilisateur valide.");
        }

        User user = userRepository.findById(userId)
                .filter(User::isActive)
                .orElseThrow(() -> new BadCredentialsException("Utilisateur introuvable ou accès révoqué."));

        AuthenticatedUser principal = new AuthenticatedUser(user);
        return new UsernamePasswordAuthenticationToken(principal, jwt, principal.getAuthorities());
    }
}
