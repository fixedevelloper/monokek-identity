package com.monokek.identity.web.dto;

import com.monokek.identity.domain.Permission;
import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.User;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

public record StaffDto(
        Long id,
        UUID uuid,
        String name,
        String email,
        String phone,
        boolean isActive,
        String role,
        List<String> roles,
        List<String> permissions,
        String createdAt,
        String updatedAt,
        Long branchId
) {

    private static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    public static StaffDto from(User user) {
        return new StaffDto(
                user.getId(),
                user.getUuid(),
                user.getName(),
                user.getEmail(),
                user.getPhone(),
                user.isActive(),
                user.getRoles().stream().findFirst().map(Role::getName).orElse(null),
                user.getRoles().stream().map(Role::getName).toList(),
                user.getAllPermissionNames().stream().toList(),
                user.getCreatedAt() == null ? null : user.getCreatedAt().format(FORMAT),
                user.getUpdatedAt() == null ? null : user.getUpdatedAt().format(FORMAT),
                user.getBranchId()
        );
    }

    public record RoleOption(Long id, String name, List<String> permissions) {
        public static RoleOption from(Role role) {
            return new RoleOption(
                    role.getId(),
                    role.getName(),
                    role.getPermissions().stream().map(Permission::getName).toList());
        }
    }

    public record PermissionOption(Long id, String name, String label) {
        public static PermissionOption from(Permission permission) {
            String label = permission.getName()
                    .replace("_", " ")
                    .replace("create", "Créer")
                    .replace("view", "Voir")
                    .replace("manage", "Gérer");
            return new PermissionOption(permission.getId(), permission.getName(), label);
        }
    }
}
