package com.monokek.identity.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record PinLookupRequest(
        @NotNull Long branchId,
        @NotBlank @Pattern(regexp = "\\d{4}", message = "Le code PIN doit contenir exactement 4 chiffres.") String pin
) {
}
