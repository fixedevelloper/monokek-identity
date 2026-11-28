package com.monokek.identity.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The POS client is only INSERTED when missing, so a lifetime change in config must be re-applied onto the row that an
 * existing deployment already has — otherwise the new session length would never reach it. Real JDBC repository (H2).
 */
class ClientSeederTest {

    private static final ApplicationArguments NO_ARGS = mock(ApplicationArguments.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();
    private EmbeddedDatabase db;
    private JdbcRegisteredClientRepository repository;

    @BeforeEach
    void setUp() {
        db = new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql").build();
        repository = new JdbcRegisteredClientRepository(new JdbcTemplate(db));
    }

    @AfterEach
    void tearDown() {
        db.shutdown();
    }

    private ClientSeeder seeder(long accessMinutes, long refreshDays) {
        return new ClientSeeder(repository, encoder, "pos", "pos-secret", "svc", "svc-secret", "int", "int-secret",
                accessMinutes, refreshDays);
    }

    /** What a deployment installed before the lifetimes became configurable has in its table: 30 min / 30 days. */
    private RegisteredClient legacyPosClient() {
        return RegisteredClient.withId("legacy-id").clientId("pos").clientSecret(encoder.encode("pos-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30)).refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false).build())
                .build();
    }

    @Test
    void freshInstallGetsConfiguredLifetimes() {
        seeder(60, 90).run(NO_ARGS);

        TokenSettings t = repository.findByClientId("pos").getTokenSettings();
        assertThat(t.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(60));
        assertThat(t.getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(90));
        assertThat(t.isReuseRefreshTokens()).isFalse();
    }

    @Test
    void existingClientIsUpdatedInPlaceKeepingIdentityAndSecret() {
        repository.save(legacyPosClient());

        seeder(60, 90).run(NO_ARGS);

        RegisteredClient pos = repository.findByClientId("pos");
        assertThat(pos.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(60));
        assertThat(pos.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(90));
        assertThat(pos.getTokenSettings().isReuseRefreshTokens()).as("rotation setting untouched").isFalse();
        assertThat(pos.getId()).as("same row, not a new client").isEqualTo("legacy-id");
        assertThat(encoder.matches("pos-secret", pos.getClientSecret())).isTrue();
        assertThat(pos.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.REFRESH_TOKEN);
    }

    @Test
    void secondBootWithSameConfigChangesNothing() {
        seeder(60, 90).run(NO_ARGS);
        RegisteredClient first = repository.findByClientId("pos");

        seeder(60, 90).run(NO_ARGS);

        RegisteredClient second = repository.findByClientId("pos");
        assertThat(second.getId()).isEqualTo(first.getId());
        assertThat(second.getClientSecret()).isEqualTo(first.getClientSecret());
        assertThat(second.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(90));
    }

    @Test
    void loweringTheConfigIsAlsoApplied() {
        seeder(60, 90).run(NO_ARGS);

        seeder(15, 7).run(NO_ARGS);

        TokenSettings t = repository.findByClientId("pos").getTokenSettings();
        assertThat(t.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
        assertThat(t.getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
    }
}
