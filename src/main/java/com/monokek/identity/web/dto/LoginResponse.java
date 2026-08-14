package com.monokek.identity.web.dto;

/**
 * Same shape as the pre-extraction {@code AuthController::login} payload
 * ({@code {user: {id, name, role}, token}}) — kept identical so the existing
 * frontend/Tauri clients don't need to change, even though under the hood this
 * now goes through the OAuth2 password grant. {@code refreshToken} is new: the
 * old stateless-JWT design had nothing to refresh with.
 */
public record LoginResponse(UserSummary user, String token, String refreshToken, long expiresInSeconds) {
}
