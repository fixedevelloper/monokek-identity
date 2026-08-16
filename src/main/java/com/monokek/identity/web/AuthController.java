package com.monokek.identity.web;

import com.monokek.identity.application.AuthService;
import com.monokek.identity.application.LoginService;
import com.monokek.identity.common.ApiResponse;
import com.monokek.identity.security.AuthenticatedUser;
import com.monokek.identity.web.dto.*;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final LoginService loginService;
    private final AuthService authService;

    public AuthController(LoginService loginService, AuthService authService) {
        this.loginService = loginService;
        this.authService = authService;
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return new ApiResponse<>("success", null, loginService.login(request), null);
    }

    @GetMapping("/me")
    public StaffDto me(@AuthenticationPrincipal AuthenticatedUser principal) {
        return StaffDto.from(principal.getUser());
    }

    @PostMapping("/auth/verify-pin")
    public ApiResponse<UserSummary> verifyPin(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @Valid @RequestBody VerifyPinRequest request) {
        authService.verifyPin(principal.getUser(), request.pin());
        var user = principal.getUser();
        String role = user.getRoles().stream().findFirst().map(r -> r.getName()).orElse(null);
        return ApiResponse.success(new UserSummary(user.getId(), user.getName(), role), "Accès autorisé");
    }

    @PostMapping("/auth/update-pin")
    public ApiResponse<Void> updatePin(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @Valid @RequestBody UpdatePinRequest request) {
        authService.updatePin(principal.getUser(), request.pin());
        return ApiResponse.message("Code PIN mis à jour avec succès.");
    }

    /**
     * Identifies which colleague in {@code branchId} owns {@code pin} —
     * used by a shared POS terminal for self-service clock-in/out, where the
     * person punching in isn't the terminal's own logged-in session. Only
     * requires an authenticated caller (the terminal itself), not a specific
     * role: any staff member operating the terminal can look up a colleague.
     */
    @PostMapping("/auth/lookup-pin")
    public ApiResponse<UserSummary> lookupPin(@Valid @RequestBody PinLookupRequest request) {
        var user = authService.lookupByPin(request.branchId(), request.pin());
        String role = user.getRoles().stream().findFirst().map(r -> r.getName()).orElse(null);
        return ApiResponse.success(new UserSummary(user.getId(), user.getName(), role), "Utilisateur identifié");
    }

    @PostMapping("/auth/update-password")
    public ApiResponse<Void> updatePassword(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @Valid @RequestBody UpdatePasswordRequest request) {
        authService.updatePassword(
                principal.getUser(), request.oldPassword(), request.newPassword(), request.newPasswordConfirmation());
        return ApiResponse.message("Mot de passe mis à jour.");
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout() {
        // The refresh token is what actually matters now (see TokenIssuer) — the
        // frontend simply discards both; there's no per-access-token revocation.
        return ApiResponse.message("Déconnexion réussie");
    }
}
