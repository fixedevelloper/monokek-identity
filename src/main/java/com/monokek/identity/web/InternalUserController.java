package com.monokek.identity.web;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import com.monokek.identity.web.dto.UserNamesResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Replaces the old in-process {@code identity.UserDirectory} interface for callers
 * outside this process (monokek-spring). Protected by the {@code internal.users.read}
 * scope (see DefaultSecurityConfig, ClientSeeder) — only the monokek-spring-service
 * client_credentials client can call this, never an end-user token.
 */
@RestController
public class InternalUserController {

    private final UserRepository userRepository;

    public InternalUserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/internal/users")
    public UserNamesResponse namesByIds(@RequestParam List<Long> ids) {
        Map<Long, String> names = userRepository.findByIdIn(ids).stream()
                .collect(Collectors.toMap(User::getId, User::getName));
        return new UserNamesResponse(names);
    }
}
