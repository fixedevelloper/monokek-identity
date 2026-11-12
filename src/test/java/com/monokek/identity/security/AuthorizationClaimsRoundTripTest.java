package com.monokek.identity.security;

import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The claims {@link UserClaimsTokenCustomizer} adds are persisted with the authorization on every refresh and must be READABLE again:
 * with {@code List.toList()} / {@code Long} values the row was written but refused at the next read ("not in the allowlist"), so a
 * session survived exactly ONE refresh. Uses the real {@link JdbcOAuth2AuthorizationService} (H2) — an in-memory service would never notice.
 */
class AuthorizationClaimsRoundTripTest {

    private EmbeddedDatabase db;
    private JdbcOAuth2AuthorizationService service;
    private static final RegisteredClient CLIENT = RegisteredClient.withId("c1").clientId("pos")
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();

    @BeforeEach
    void setUp() {
        db = new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql").build();
        service = new JdbcOAuth2AuthorizationService(new JdbcTemplate(db), new InMemoryRegisteredClientRepository(CLIENT));
    }

    @AfterEach
    void tearDown() {
        db.shutdown();
    }

    private static User user(Long branchId) {
        User u = mock(User.class);
        Role role = mock(Role.class);
        when(role.getName()).thenReturn("waiter");
        when(u.getUuid()).thenReturn(UUID.randomUUID());
        when(u.getName()).thenReturn("Awa");
        when(u.getRoles()).thenReturn(Set.of(role));
        when(u.getAllPermissionNames()).thenReturn(Set.of());
        when(u.getBranchId()).thenReturn(branchId);
        return u;
    }

    /** The claims exactly as the customizer produces them during a refresh. */
    private static Map<String, Object> customizedClaims(User user) {
        UserRepository repo = mock(UserRepository.class);
        when(repo.findById(9L)).thenReturn(Optional.of(user));
        when(user.isActive()).thenReturn(true);
        JwtEncodingContext context = JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder().subject("9"))
                .registeredClient(CLIENT)
                .principal(new UsernamePasswordAuthenticationToken("9", null))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        new UserClaimsTokenCustomizer(repo).customize(context);
        return context.getClaims().build().getClaims();
    }

    private OAuth2Authorization saveWithClaims(Map<String, Object> claims, String id) {
        Instant now = Instant.now();
        OAuth2Authorization a = OAuth2Authorization.withRegisteredClient(CLIENT).id(id).principalName("9")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at-" + id, now, now.plusSeconds(60)),
                        m -> m.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .token(new OAuth2RefreshToken("rt-" + id, now, now.plusSeconds(3600)))
                .build();
        service.save(a);
        return a;
    }

    @Test
    void claimsOfABranchAccountCanBeReadBackAfterTheyWereStored() {
        saveWithClaims(customizedClaims(user(7L)), "a1");

        assertThatCode(() -> service.findByToken("rt-a1", OAuth2TokenType.REFRESH_TOKEN)).doesNotThrowAnyException();
        OAuth2Authorization back = service.findByToken("rt-a1", OAuth2TokenType.REFRESH_TOKEN);
        assertThat(back).isNotNull();
        Map<String, Object> claims = back.getAccessToken().getClaims();
        assertThat(((Number) claims.get("branch_id")).longValue()).isEqualTo(7L);
        assertThat(claims.get("roles")).isEqualTo(java.util.List.of("waiter"));
    }

    @Test
    void claimsOfAnAccountWithoutBranchCanBeReadBackToo() {
        saveWithClaims(customizedClaims(user(null)), "a2");
        assertThat(service.findByToken("rt-a2", OAuth2TokenType.REFRESH_TOKEN)).isNotNull();
    }

    @Test
    void theOldClaimTypesWereTheProblem() {
        // what the customizer used to put in: an immutable list and a Long. Documents WHY the types matter.
        saveWithClaims(Map.of("roles", java.util.List.of("waiter"), "branch_id", 7L), "a3");
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> service.findByToken("rt-a3", OAuth2TokenType.REFRESH_TOKEN));
    }

    @Test
    void graceLookupOnAnUnreadableRowAnswersInvalidTokenInsteadOfThrowing() {
        // rows written by the previous version cannot be read. The grace window must then say "unknown token" (a clean invalid_grant the
        // client handles) rather than surface a deserialization exception as a server error.
        var delegate = mock(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService.class);
        Instant now = Instant.now();
        OAuth2Authorization before = OAuth2Authorization.withRegisteredClient(CLIENT).id("a4").principalName("9")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).token(new OAuth2RefreshToken("R1", now, now.plusSeconds(3600))).build();
        OAuth2Authorization rotated = OAuth2Authorization.from(before).token(new OAuth2RefreshToken("R2", now, now.plusSeconds(3600))).build();
        when(delegate.findById("a4")).thenReturn(before).thenThrow(new IllegalArgumentException("not in the allowlist"));
        var grace = new GraceRefreshAuthorizationService(delegate, java.time.Duration.ofSeconds(60));

        grace.save(rotated); // remembers R1 -> a4

        assertThatCode(() -> grace.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN)).doesNotThrowAnyException();
        assertThat(grace.findByToken("R1", OAuth2TokenType.REFRESH_TOKEN)).isNull();
    }
}
