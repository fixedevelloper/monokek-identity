package com.monokek.identity.web;

import com.monokek.identity.application.StaffService;
import com.monokek.identity.common.ApiResponse;
import com.monokek.identity.security.AuthenticatedUser;
import com.monokek.identity.web.dto.StaffCreateRequest;
import com.monokek.identity.web.dto.StaffDto;
import com.monokek.identity.web.dto.StaffUpdateRequest;
import com.monokek.identity.web.dto.UpdatePermissionsRequest;
import com.monokek.identity.web.dto.UpdatePinRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/staff")
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
public class StaffController {

    private final StaffService staffService;

    public StaffController(StaffService staffService) {
        this.staffService = staffService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('view_staff'))")
    public ApiResponse<List<StaffDto>> index() {
        return ApiResponse.success(staffService.list());
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('manage_users'))")
    public ApiResponse<StaffDto> store(@Valid @RequestBody StaffCreateRequest request) {
        return ApiResponse.success(staffService.create(request), "Membre du staff créé avec succès");
    }

    @RequestMapping(value = "/{uuid}", method = {RequestMethod.PUT, RequestMethod.PATCH})
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('manage_users'))")
    public ApiResponse<StaffDto> update(@PathVariable UUID uuid, @RequestBody StaffUpdateRequest request) {
        return ApiResponse.success(staffService.update(uuid, request), "Profil mis à jour");
    }

    @DeleteMapping("/{uuid}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('manage_users'))")
    public ApiResponse<Void> destroy(@PathVariable UUID uuid, @AuthenticationPrincipal AuthenticatedUser principal) {
        staffService.delete(uuid, principal.getUser().getId());
        return ApiResponse.message("Accès révoqué avec succès");
    }

    @GetMapping("/roles")
    public ApiResponse<List<StaffDto.RoleOption>> roles() {
        return ApiResponse.success(staffService.listRoles());
    }

    /** {@code edit_permissions} specifically, not just {@code manage_users} — granting permissions is more
     * sensitive than ordinary staff CRUD (it can be used to self-escalate), so it gets its own permission. */
    @GetMapping("/permissions/list")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('edit_permissions'))")
    public ApiResponse<List<StaffDto.PermissionOption>> permissions() {
        return ApiResponse.success(staffService.listPermissions());
    }

    @PutMapping("/{uuid}/permissions")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and (hasRole('ADMIN') or hasAuthority('edit_permissions'))")
    public ApiResponse<Integer> updatePermissions(@PathVariable UUID uuid, @Valid @RequestBody UpdatePermissionsRequest request) {
        int count = staffService.updatePermissions(uuid, request.permissions());
        return ApiResponse.success(count, "Permissions mises à jour avec succès");
    }

    /** Admin-side PIN onboarding — see StaffService#setPin. */
    @PutMapping("/{uuid}/pin")
    public ApiResponse<Void> setPin(@PathVariable UUID uuid, @Valid @RequestBody UpdatePinRequest request) {
        staffService.setPin(uuid, request.pin());
        return ApiResponse.message("Code PIN défini avec succès");
    }
}
