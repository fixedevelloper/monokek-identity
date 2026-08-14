package com.monokek.identity.application;

import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import com.monokek.identity.security.TokenIssuer;
import com.monokek.identity.web.dto.LoginRequest;
import com.monokek.identity.web.dto.LoginResponse;
import com.monokek.identity.web.dto.UserSummary;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

/**
 * Backs {@code POST /api/login} — kept JSON-in/JSON-out for the existing frontend
 * (see LoginResponse) instead of exposing raw OAuth2 form-encoding to it. Issues
 * exactly the same token an OAuth2 client would get from {@code /oauth2/token}
 * with the custom password grant, via the same {@link TokenIssuer}.
 */
@Service
public class LoginService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenIssuer tokenIssuer;
    private final RegisteredClientRepository registeredClientRepository;
    private final ActivityNotifier activityNotifier;
    private final String posClientId;

    public LoginService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenIssuer tokenIssuer,
            RegisteredClientRepository registeredClientRepository,
            ActivityNotifier activityNotifier,
            @Value("${app.identity.clients.pos.client-id}") String posClientId) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenIssuer = tokenIssuer;
        this.registeredClientRepository = registeredClientRepository;
        this.activityNotifier = activityNotifier;
        this.posClientId = posClientId;
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Les identifiants sont incorrects."));
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Les identifiants sont incorrects.");
        }
        // Every other auth path (PasswordGrantAuthenticationProvider, the resource-server
        // converter, the refresh-token claims customizer) filters on isActive() — this JSON
        // endpoint must too, or a deactivated staff member (isActive=false, no soft-delete —
        // see StaffService#delete vs #update) could still log in and get a fully-privileged
        // token here even though the same credentials are correctly rejected at /oauth2/token.
        if (!user.isActive()) {
            throw new BadCredentialsException("Les identifiants sont incorrects.");
        }

        RegisteredClient posClient = registeredClientRepository.findByClientId(posClientId);
        TokenIssuer.IssuedTokens tokens = tokenIssuer.issue(user, posClient);

        activityNotifier.userLoggedIn(user.getId(), user.getUuid(), request.deviceName());

        OAuth2AccessToken accessToken = tokens.accessToken();
        long expiresInSeconds = Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds();
        String role = user.getRoles().stream().findFirst().map(Role::getName).orElse("waiter");

        return new LoginResponse(
                new UserSummary(user.getId(), user.getName(), role),
                accessToken.getTokenValue(),
                tokens.refreshToken() == null ? null : tokens.refreshToken().getTokenValue(),
                expiresInSeconds);
    }
}
