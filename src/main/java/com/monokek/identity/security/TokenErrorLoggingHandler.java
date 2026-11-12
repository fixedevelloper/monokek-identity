package com.monokek.identity.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Token endpoint error handler: same JSON answer as Spring's default (400, 401 for invalid_client),
 * plus a WARN line for every {@code invalid_grant} so unexpected logouts can be traced
 * (which grant, which terminal, which refresh token). The token itself is never logged, only a
 * short SHA-256 fingerprint to correlate repeated attempts.
 */
public class TokenErrorLoggingHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(TokenErrorLoggingHandler.class);

    private final HttpMessageConverter<OAuth2Error> converter = new OAuth2ErrorHttpMessageConverter();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        OAuth2Error error = exception instanceof OAuth2AuthenticationException oae
                ? oae.getError()
                : new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);

        if (OAuth2ErrorCodes.INVALID_GRANT.equals(error.getErrorCode())) {
            log.warn("invalid_grant: grant_type={} refresh_token_fp={} ip={} user-agent={} detail={}",
                    request.getParameter("grant_type"),
                    fingerprint(request.getParameter("refresh_token")),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent"),
                    error.getDescription());
        }

        HttpStatus status = OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())
                ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
        response.setStatus(status.value());
        converter.write(error, null, new ServletServerHttpResponse(response));
    }

    static String fingerprint(String token) {
        if (token == null || token.isEmpty()) {
            return "-";
        }
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d, 0, 4);
        } catch (Exception e) {
            return "?";
        }
    }
}
