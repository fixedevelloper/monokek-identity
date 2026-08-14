package com.monokek.identity.infrastructure.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Fetches and caches a client_credentials token this service uses to call OUT to
 * monokek-spring's {@code /internal/activity-log} (see SpringActivityLogClient) —
 * a self-call to this same service's own token endpoint, using the
 * {@code monokek-identity-internal} client ClientSeeder registers.
 */
@Component
class SpringServiceTokenClient {

    private static final Logger log = LoggerFactory.getLogger(SpringServiceTokenClient.class);

    private final RestClient restClient;
    private final String clientId;
    private final String clientSecret;

    private volatile CachedToken cached;

    SpringServiceTokenClient(
            @Value("${app.identity.issuer}") String issuer,
            @Value("${app.identity.clients.internal.client-id}") String clientId,
            @Value("${app.identity.clients.internal.client-secret}") String clientSecret) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(3));
        requestFactory.setReadTimeout(Duration.ofSeconds(5));
        this.restClient = RestClient.builder().baseUrl(issuer + "/oauth2/token").requestFactory(requestFactory).build();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    synchronized String accessTokenOrNull() {
        Instant now = Instant.now();
        if (cached != null && cached.expiresAt.isAfter(now)) {
            return cached.value;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = restClient.post()
                    .headers(headers -> headers.setBasicAuth(clientId, clientSecret))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("grant_type=client_credentials&scope=internal.activity-log.write")
                    .retrieve()
                    .body(Map.class);
            if (response == null || response.get("access_token") == null || response.get("expires_in") == null) {
                return null;
            }
            String token = (String) response.get("access_token");
            int expiresIn = ((Number) response.get("expires_in")).intValue();
            cached = new CachedToken(token, now.plusSeconds(Math.max(expiresIn - 30, 0)));
            return token;
        } catch (Exception e) {
            log.warn("Impossible d'obtenir un token client_credentials pour appeler monokek-spring: {}", e.getMessage());
            return null;
        }
    }

    private record CachedToken(String value, Instant expiresAt) {
    }
}
