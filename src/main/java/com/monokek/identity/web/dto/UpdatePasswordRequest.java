package com.monokek.identity.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordRequest(
        @NotBlank String oldPassword,
        @NotBlank @Size(min = 8) String newPassword,
        @NotBlank String newPasswordConfirmation
) {
}
