package com.monokek.identity.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record StaffCreateRequest(
        @NotBlank String name,
        @NotBlank @Email String email,
        String phone,
        @NotBlank @Size(min = 8) String password,
        @NotBlank String role,
        Long branchId
) {
}
