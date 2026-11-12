package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.security.AttemptLimiter;
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
    private final AttemptLimiter attemptLimiter;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, AttemptLimiter attemptLimiter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.attemptLimiter = attemptLimiter;
    }

    @Transactional(readOnly = true)
    public void verifyPin(User user, String pin) {
        String key = AttemptLimiter.userPinKey(user.getId());
        attemptLimiter.check(key, AttemptLimiter.PIN_MAX_FAILURES, AttemptLimiter.PIN_WINDOW);
        if (user.getPinCode() == null || !passwordEncoder.matches(pin, user.getPinCode())) {
            attemptLimiter.recordFailure(key, AttemptLimiter.PIN_WINDOW);
            throw new ApiException(HttpStatus.BAD_REQUEST, "Code PIN invalide");
        }
        attemptLimiter.reset(key);
    }

    @Transactional
    public void updatePin(User user, String pin) {
        ensurePinIsUniqueInBranch(user.getBranchId(), pin, user.getId());
        user.setPinCode(passwordEncoder.encode(pin));
        userRepository.save(user);
    }

    /**
     * Resolves which active user in {@code branchId} owns {@code pin} — the
     * lookup a shared POS terminal needs for self-service clock-in/out
     * (staffing.TimeClockController), where the person punching in isn't the
     * terminal's own logged-in session. Bcrypt hashes are one-way, so this
     * has to brute-force every active candidate in the branch — same
     * approach as {@link #ensurePinIsUniqueInBranch}, which is exactly what
     * keeps this lookup unambiguous (two colleagues in the same branch can
     * never end up sharing a PIN).
     */
    @Transactional(readOnly = true)
    public User lookupByPin(Long branchId, String pin) {
        // Counted per branch, not per caller: the lookup tests a PIN against every colleague of the
        // branch, so what an attacker brute-forces is the branch's whole PIN space.
        String key = AttemptLimiter.branchPinKey(branchId);
        attemptLimiter.check(key, AttemptLimiter.PIN_MAX_FAILURES, AttemptLimiter.PIN_WINDOW);
        User found = userRepository.findByBranchIdAndActiveTrue(branchId).stream()
                .filter(candidate -> candidate.getPinCode() != null && passwordEncoder.matches(pin, candidate.getPinCode()))
                .findFirst()
                .orElse(null);
        if (found == null) {
            attemptLimiter.recordFailure(key, AttemptLimiter.PIN_WINDOW);
            throw ApiException.badRequest("Code PIN invalide");
        }
        return found;
    }

    /** No-op when {@code branchId} is null — collisions only matter within the pool a branch-scoped lookup actually searches. */
    private void ensurePinIsUniqueInBranch(Long branchId, String pin, Long excludingUserId) {
        if (branchId == null) return;
        boolean collision = userRepository.findByBranchIdAndActiveTrue(branchId).stream()
                .filter(candidate -> !candidate.getId().equals(excludingUserId))
                .anyMatch(candidate -> candidate.getPinCode() != null && passwordEncoder.matches(pin, candidate.getPinCode()));
        if (collision) {
            throw ApiException.conflict("Ce code PIN est déjà utilisé par un autre membre de l'équipe.");
        }
    }

    @Transactional
    public void updatePassword(User user, String oldPassword, String newPassword, String confirmation) {
        // A stolen access token must not be enough to guess the account's current password.
        String key = AttemptLimiter.passwordChangeKey(user.getId());
        attemptLimiter.check(key, AttemptLimiter.LOGIN_MAX_FAILURES, AttemptLimiter.LOGIN_WINDOW);
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            attemptLimiter.recordFailure(key, AttemptLimiter.LOGIN_WINDOW);
            throw ApiException.badRequest("L'ancien mot de passe est incorrect.");
        }
        attemptLimiter.reset(key);
        if (!newPassword.equals(confirmation)) {
            throw ApiException.badRequest("La confirmation du mot de passe ne correspond pas.");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
}
