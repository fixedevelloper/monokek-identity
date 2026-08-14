package com.monokek.identity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

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

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http, JwtDecoder jwtDecoder, JwtToAuthenticatedUserConverter converter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/api/login").permitAll()
                        .requestMatchers("/api/admin/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/internal/**").hasAuthority("SCOPE_internal.users.read")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(converter)));

        return http.build();
    }
}
