package com.monokek.identity.web.dto;

public record StaffUpdateRequest(
        String name,
        String email,
        String phone,
        Boolean isActive,
        String role,
        Long branchId,
        boolean clearBranchId
) {
}
