package com.monokek.identity.application;

import java.util.List;
import java.util.UUID;

/**
 * Replaces the old in-process Spring Modulith events (StaffCreatedEvent, etc.) that
 * monokek-spring's ActivityLogListener used to consume directly. Now that user
 * management lives in a separate process, this is a best-effort notification: a
 * failure here (e.g. monokek-spring is down) must NEVER block the identity operation
 * it's reporting on — see infrastructure.client.HttpActivityNotifier.
 */
public interface ActivityNotifier {

    void staffCreated(Long userId, UUID uuid, String name, String role);

    void permissionsUpdated(Long userId, UUID uuid, List<String> permissionNames);

    void accessRevoked(Long userId, UUID uuid, Long revokedByUserId);

    void userLoggedIn(Long userId, UUID uuid, String deviceName);
}
