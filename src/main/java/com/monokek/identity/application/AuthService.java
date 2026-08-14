package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Credential verification/management: PIN and password. Login itself (issuing a
 * token) is handled by the custom OAuth2 password grant in the security package,
 * not here — these are plain, already-authenticated operations on top of an
 * existing session, exactly like before the extraction.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public void verifyPin(User user, String pin) {
        if (user.getPinCode() == null || !passwordEncoder.matches(pin, user.getPinCode())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Code PIN invalide");
        }
    }

    @Transactional
    public void updatePin(User user, String pin) {
        user.setPinCode(passwordEncoder.encode(pin));
        userRepository.save(user);
    }

    @Transactional
    public void updatePassword(User user, String oldPassword, String newPassword, String confirmation) {
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw ApiException.badRequest("L'ancien mot de passe est incorrect.");
        }
        if (!newPassword.equals(confirmation)) {
            throw ApiException.badRequest("La confirmation du mot de passe ne correspond pas.");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
}
