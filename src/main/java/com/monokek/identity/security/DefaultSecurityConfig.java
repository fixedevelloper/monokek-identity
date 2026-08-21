package com.monokek.identity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.monokek.identity.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.List;

/**
 * Ordinary OAuth2 resource-server chain protecting this service's own plain REST
 * endpoints (staff management, /me, PIN/password) — as opposed to
 * AuthorizationServerConfig's chain, which only matches the token/JWKS/OIDC
 * endpoints. This service therefore validates its own tokens exactly the same way
 * monokek-spring and pms-modulith do, just without the network hop.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class DefaultSecurityConfig {

    private final ObjectMapper objectMapper;

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    public DefaultSecurityConfig(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http, JwtDecoder jwtDecoder, JwtToAuthenticatedUserConverter converter) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/api/login").permitAll()
                        .requestMatchers("/api/admin/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/internal/**").hasAuthority("SCOPE_internal.users.read")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(converter)))
                // Without these, a 401 (no/invalid/expired token) or 403 (@PreAuthorize/hasAnyRole
                // denial — the latter is an AccessDeniedException thrown by AOP around the
                // controller call, which GlobalExceptionHandler's @RestControllerAdvice can't see:
                // Spring Security's ExceptionTranslationFilter catches it first) fall through to
                // Spring Security's bare default responses instead of this app's ApiResponse
                // envelope — same fix as monokek-spring's SecurityConfig.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(this::writeUnauthenticated)
                        .accessDeniedHandler(this::writeForbidden));

        return http.build();
    }

    private void writeUnauthenticated(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) throws IOException {
        writeJson(response, HttpStatus.UNAUTHORIZED, "Authentification requise");
    }

    private void writeForbidden(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) throws IOException {
        writeJson(response, HttpStatus.FORBIDDEN, "Action non autorisée");
    }

    private void writeJson(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(ApiResponse.error(message)));
    }

    /** Also used by {@link AuthorizationServerConfig}'s own filter chain (its own {@code @Bean}
     * there would just be a second, drifting copy) — the POS app's direct browser/webview calls
     * to {@code /oauth2/token} (refresh_token grant) need the exact same allowed-origins as every
     * other endpoint, and that chain doesn't share this one's {@code .cors(...)} configuration. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
