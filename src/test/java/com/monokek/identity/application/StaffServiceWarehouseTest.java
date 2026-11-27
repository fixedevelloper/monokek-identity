package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.User;
import com.monokek.identity.web.dto.StaffCreateRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A storekeeper without a branch would be read as the owner by the stock services: the account must have one. */
class StaffServiceWarehouseTest {

    private StaffAccessPolicy policy;
    private StaffService service;
    private User admin;

    @BeforeEach
    void setUp() {
        policy = mock(StaffAccessPolicy.class);
        service = new StaffService(null, null, null, null, null, null, policy);
        admin = mock(User.class);
        Role role = mock(Role.class);
        when(role.getName()).thenReturn("admin");
        when(admin.getRoles()).thenReturn(Set.of(role));
    }

    @Test
    void creatingAStorekeeperWithoutABranchIsRefused() {
        when(policy.checkCreate(admin, "warehouse", null)).thenReturn(null);

        assertThatThrownBy(() -> service.create(new StaffCreateRequest("Store", "store@x.com", null, "password1", "warehouse", null), admin))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("magasinier");
    }
}
