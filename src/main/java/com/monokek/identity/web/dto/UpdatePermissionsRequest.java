package com.monokek.identity.web.dto;

import jakarta.validation.constraints.NotNull;

import java.util.List;

public record UpdatePermissionsRequest(@NotNull List<String> permissions) {
}
