package com.monokek.identity.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.monokek.identity.security.PasswordGrantAuthenticationToken.GRANT_TYPE;

/**
 * Recognizes {@code grant_type=urn:monokek:params:oauth:grant-type:password} on the
 * token endpoint and extracts {@code username}/{@code password}/{@code scope}.
 */
public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }
        return doConvert(request);
    }

    private Authentication doConvert(HttpServletRequest request) {
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String username = request.getParameter(OAuth2ParameterNames.USERNAME);
        String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);

        if (!StringUtils.hasText(username) || countOccurrences(request, OAuth2ParameterNames.USERNAME) != 1) {
            return null;
        }
        if (!StringUtils.hasText(password) || countOccurrences(request, OAuth2ParameterNames.PASSWORD) != 1) {
            return null;
        }

        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                    && !key.equals(OAuth2ParameterNames.USERNAME)
                    && !key.equals(OAuth2ParameterNames.PASSWORD)
                    && !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, values.length == 1 ? values[0] : values);
            }
        });

        return new PasswordGrantAuthenticationToken(clientPrincipal, username, password, requestedScopes, additionalParameters);
    }

    private static int countOccurrences(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        return values == null ? 0 : values.length;
    }
}
