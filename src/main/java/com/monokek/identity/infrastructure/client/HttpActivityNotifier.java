package com.monokek.identity.infrastructure.client;

import com.monokek.identity.application.ActivityNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Calls monokek-spring's {@code /internal/activity-log/*} webhook (see
 * settings.web.InternalActivityLogController there) so staff/login activity still
 * ends up in the audit trail now that it no longer happens in the same process.
 * {@code @Async}: a slow or unreachable monokek-spring must never delay or fail a
 * login/staff-management operation here — this is best-effort reporting, not a
 * dependency. Failures are logged and swallowed, never rethrown.
 */
@Component
public class HttpActivityNotifier implements ActivityNotifier {

    private static final Logger log = LoggerFactory.getLogger(HttpActivityNotifier.class);

    private final RestClient restClient;
    private final SpringServiceTokenClient tokenClient;

    public HttpActivityNotifier(@Value("${app.identity.monokek-spring-api-url}") String monokekSpringApiUrl, SpringServiceTokenClient tokenClient) {
        this.restClient = RestClient.builder().baseUrl(monokekSpringApiUrl).build();
        this.tokenClient = tokenClient;
    }

    @Override
    @Async
    public void staffCreated(Long userId, UUID uuid, String name, String role) {
        post("/internal/activity-log/staff-created", new StaffCreatedBody(userId, uuid, name, role, Instant.now()));
    }

    @Override
    @Async
    public void permissionsUpdated(Long userId, UUID uuid, List<String> permissionNames) {
        post("/internal/activity-log/staff-permissions-updated",
                new StaffPermissionsUpdatedBody(userId, uuid, permissionNames, Instant.now()));
    }

    @Override
    @Async
    public void accessRevoked(Long userId, UUID uuid, Long revokedByUserId) {
        post("/internal/activity-log/staff-access-revoked",
                new StaffAccessRevokedBody(userId, uuid, revokedByUserId, Instant.now()));
    }

    @Override
    @Async
    public void userLoggedIn(Long userId, UUID uuid, String deviceName) {
        post("/internal/activity-log/user-logged-in", new UserLoggedInBody(userId, uuid, deviceName, Instant.now()));
    }

    private void post(String path, Object body) {
        String token = tokenClient.accessTokenOrNull();
        if (token == null) {
            return;
        }
        try {
            restClient.post()
                    .uri(path)
                    .headers(headers -> headers.setBearerAuth(token))
                    .body(body)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            log.warn("Échec de l'appel du webhook d'audit monokek-spring {}: {}", path, e.getMessage());
        }
    }

    private record UserLoggedInBody(Long userId, UUID userUuid, String deviceName, Instant occurredAt) {
    }

    private record StaffCreatedBody(Long userId, UUID userUuid, String name, String role, Instant occurredAt) {
    }

    private record StaffPermissionsUpdatedBody(Long userId, UUID userUuid, List<String> permissions, Instant occurredAt) {
    }

    private record StaffAccessRevokedBody(Long userId, UUID userUuid, Long revokedByUserId, Instant occurredAt) {
    }
}
