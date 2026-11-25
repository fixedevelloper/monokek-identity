package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StaffAccessPolicyTest {

    private final StaffAccessPolicy policy = new StaffAccessPolicy();

    private static User user(long id, String role, Long branchId, String... permissions) {
        Role r = mock(Role.class);
        when(r.getName()).thenReturn(role);
        User u = mock(User.class);
        when(u.getId()).thenReturn(id);
        when(u.getRoles()).thenReturn(Set.of(r));
        when(u.getBranchId()).thenReturn(branchId);
        when(u.getAllPermissionNames()).thenReturn(Set.of(permissions));
        return u;
    }

    private static void forbidden(Runnable action) {
        ApiException e = assertThrows(ApiException.class, action::run);
        assertEquals(HttpStatus.FORBIDDEN, e.getStatus());
    }

    @Test
    void managerCannotCreateAnAdmin() {
        User manager = user(2, "manager", 1L, "manage_users");
        forbidden(() -> policy.checkCreate(manager, "admin", 1L));
        forbidden(() -> policy.checkCreate(manager, "super-admin", 1L));
    }

    @Test
    void managerCreatesStaffOnlyInOwnBranch() {
        User manager = user(2, "manager", 1L);
        assertEquals(1L, policy.checkCreate(manager, "waiter", null));
        assertEquals(1L, policy.checkCreate(manager, "waiter", 1L));
        forbidden(() -> policy.checkCreate(manager, "waiter", 2L));
    }

    @Test
    void adminCreatesAnything() {
        User admin = user(1, "admin", null);
        assertEquals(7L, policy.checkCreate(admin, "admin", 7L));
        assertEquals(null, policy.checkCreate(admin, "manager", null));
    }

    @Test
    void managerWithoutBranchIsRefused() {
        User manager = user(2, "manager", null);
        forbidden(() -> policy.checkCreate(manager, "waiter", null));
        forbidden(() -> policy.confinedBranch(manager));
    }

    @Test
    void managerCannotTouchAdminOrOtherBranch() {
        User manager = user(2, "manager", 1L);
        forbidden(() -> policy.checkManage(manager, user(1, "admin", 1L)));
        forbidden(() -> policy.checkManage(manager, user(3, "waiter", 2L)));
        forbidden(() -> policy.checkManage(manager, user(4, "waiter", null)));
        assertDoesNotThrow(() -> policy.checkManage(manager, user(5, "waiter", 1L)));
    }

    @Test
    void managerCannotMoveStaffToAnotherBranchOrDetachThem() {
        User manager = user(2, "manager", 1L);
        forbidden(() -> policy.checkBranchChange(manager, 2L, false));
        forbidden(() -> policy.checkBranchChange(manager, null, true));
        assertDoesNotThrow(() -> policy.checkBranchChange(manager, 1L, false));
        assertDoesNotThrow(() -> policy.checkBranchChange(user(1, "admin", null), 9L, false));
    }

    @Test
    void nonAdminCannotEditOwnPermissions() {
        User manager = user(2, "manager", 1L, "edit_permissions", "manage_stock");
        forbidden(() -> policy.checkGrant(manager, manager, List.of("manage_stock")));
    }

    @Test
    void nonAdminCannotGrantWhatTheyDoNotHold() {
        User manager = user(2, "manager", 1L, "edit_permissions", "manage_stock");
        User waiter = user(5, "waiter", 1L);
        forbidden(() -> policy.checkGrant(manager, waiter, List.of("manage_stock", "manage_settings")));
        assertDoesNotThrow(() -> policy.checkGrant(manager, waiter, List.of("manage_stock")));
    }

    @Test
    void nonAdminCannotChangePermissionsOfAnAdmin() {
        User manager = user(2, "manager", 1L, "edit_permissions", "manage_stock");
        forbidden(() -> policy.checkGrant(manager, user(1, "admin", 1L), List.of("manage_stock")));
    }

    @Test
    void adminGrantsAnything() {
        User admin = user(1, "admin", null);
        assertDoesNotThrow(() -> policy.checkGrant(admin, admin, List.of("manage_settings", "manage_branch")));
    }
}
