package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.domain.UserRepository;
import com.monokek.identity.security.AttemptLimiter;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthServicePinLimitTest {

    @Test
    void branchPinLookupIsLockedAfterTenWrongGuesses() {
        UserRepository users = mock(UserRepository.class);
        when(users.findByBranchIdAndActiveTrue(1L)).thenReturn(List.of());
        AuthService service = new AuthService(users, mock(PasswordEncoder.class), new AttemptLimiter());

        for (int i = 0; i < AttemptLimiter.PIN_MAX_FAILURES; i++) {
            ApiException wrong = assertThrows(ApiException.class, () -> service.lookupByPin(1L, "0000"));
            assertEquals(HttpStatus.BAD_REQUEST, wrong.getStatus());
        }
        ApiException locked = assertThrows(ApiException.class, () -> service.lookupByPin(1L, "1234"));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, locked.getStatus());

        // Another branch is unaffected.
        ApiException otherBranch = assertThrows(ApiException.class, () -> service.lookupByPin(2L, "1234"));
        assertEquals(HttpStatus.BAD_REQUEST, otherBranch.getStatus());
    }
}
