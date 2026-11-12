package com.monokek.identity.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wraps the real {@link OAuth2AuthorizationService} to tolerate a LOST refresh response.
 *
 * <p>Refresh tokens are rotated ({@code reuseRefreshTokens(false)}): the old value is gone from the DB
 * the moment the new pair is saved. If the response never reaches the terminal (Wi-Fi drop, wake-up,
 * timeout) the client retries with the old token, gets {@code invalid_grant} and the user is logged out
 * although the session is perfectly alive.
 *
 * <p>Here, when a refresh token is replaced by {@link #save}, its previous value is remembered for
 * {@code grace}. A refresh presented with that value inside the window resolves to the same (already
 * rotated) authorization, so the client simply receives another fresh pair. Outside the window the old
 * token is dead as before, which keeps rotation meaningful.
 *
 * <p>The memory is per instance and not persisted: after a restart the grace window is simply lost
 * (worst case = previous behaviour).
 */
public class GraceRefreshAuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(GraceRefreshAuthorizationService.class);

    private record Rotated(String authorizationId, Instant until) {}

    private final OAuth2AuthorizationService delegate;
    private final Duration grace;
    private final Clock clock;
    private final Map<String, Rotated> rotated = new ConcurrentHashMap<>();

    public GraceRefreshAuthorizationService(OAuth2AuthorizationService delegate, Duration grace) {
        this(delegate, grace, Clock.systemUTC());
    }

    GraceRefreshAuthorizationService(OAuth2AuthorizationService delegate, Duration grace, Clock clock) {
        this.delegate = delegate;
        this.grace = grace;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        if (!grace.isZero() && !grace.isNegative()) {
            OAuth2Authorization previous = delegate.findById(authorization.getId());
            String oldValue = refreshValue(previous);
            String newValue = refreshValue(authorization);
            if (oldValue != null && newValue != null && !oldValue.equals(newValue)) {
                Instant now = clock.instant();
                rotated.values().removeIf(r -> r.until().isBefore(now));
                rotated.put(oldValue, new Rotated(authorization.getId(), now.plus(grace)));
            }
        }
        delegate.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        rotated.values().removeIf(r -> r.authorizationId().equals(authorization.getId()));
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2Authorization found = delegate.findByToken(token, tokenType);
        if (found != null || tokenType == null || !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return found;
        }
        Rotated r = rotated.get(token);
        if (r == null) {
            return null;
        }
        if (r.until().isBefore(clock.instant())) {
            rotated.remove(token);
            return null;
        }
        OAuth2Authorization current = delegate.findById(r.authorizationId());
        if (current != null) {
            log.info("Refresh token deja tourne re-presente dans la fenetre de grace ({}s): reponse perdue cote client "
                    + "probable, authorization={}", grace.toSeconds(), r.authorizationId());
        }
        return current;
    }

    private static String refreshValue(OAuth2Authorization authorization) {
        if (authorization == null || authorization.getRefreshToken() == null) {
            return null;
        }
        return authorization.getRefreshToken().getToken().getTokenValue();
    }
}
