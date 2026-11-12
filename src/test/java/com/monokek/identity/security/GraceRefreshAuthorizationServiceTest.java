package com.monokek.identity.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class GraceRefreshAuthorizationServiceTest {

    private static final RegisteredClient CLIENT = RegisteredClient.withId("c1")
            .clientId("pos")
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .build();

    private static OAuth2Authorization auth(OAuth2Authorization base, String refresh) {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        OAuth2Authorization.Builder b = base == null
                ? OAuth2Authorization.withRegisteredClient(CLIENT).principalName("u").authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                : OAuth2Authorization.from(base);
        return b.token(new OAuth2RefreshToken(refresh, now, now.plus(Duration.ofDays(30)))).build();
    }

    /** Mutable clock so the test can move past the grace window. */
    private static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId z) { return this; }
        @Override public Instant instant() { return now; }
    }

    @Test
    void rotatedTokenStillResolvesInsideGraceWindowThenDies() {
        TestClock clock = new TestClock();
        var service = new GraceRefreshAuthorizationService(new InMemoryOAuth2AuthorizationService(), Duration.ofSeconds(60), clock);

        OAuth2Authorization first = auth(null, "R1");
        service.save(first);
        service.save(auth(first, "R2")); // rotation R1 -> R2

        assertNotNull(service.findByToken("R2", OAuth2TokenType.REFRESH_TOKEN));
        OAuth2Authorization viaOld = service.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN);
        assertNotNull(viaOld, "old token must resolve inside the grace window");
        assertEquals("R2", viaOld.getRefreshToken().getToken().getTokenValue());

        clock.now = clock.now.plusSeconds(61);
        assertNull(service.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN), "old token must die after the window");
    }

    @Test
    void graceDoesNotApplyToUnknownTokensOrOtherTokenTypes() {
        var service = new GraceRefreshAuthorizationService(new InMemoryOAuth2AuthorizationService(), Duration.ofSeconds(60));
        OAuth2Authorization first = auth(null, "R1");
        service.save(first);
        service.save(auth(first, "R2"));

        assertNull(service.findByToken("nope", OAuth2TokenType.REFRESH_TOKEN));
        assertNull(service.findByToken("R1", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void removedAuthorizationLeavesNoGraceBehind() {
        var service = new GraceRefreshAuthorizationService(new InMemoryOAuth2AuthorizationService(), Duration.ofSeconds(60));
        OAuth2Authorization first = auth(null, "R1");
        service.save(first);
        OAuth2Authorization second = auth(first, "R2");
        service.save(second);
        service.remove(second); // logout / revocation

        assertNull(service.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN));
    }

    @Test
    void zeroGraceKeepsStrictRotation() {
        var service = new GraceRefreshAuthorizationService(new InMemoryOAuth2AuthorizationService(), Duration.ZERO);
        OAuth2Authorization first = auth(null, "R1");
        service.save(first);
        service.save(auth(first, "R2"));
        assertNull(service.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN));
    }
}
