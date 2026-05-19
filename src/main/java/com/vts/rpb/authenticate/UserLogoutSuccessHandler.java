package com.vts.rpb.authenticate;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class UserLogoutSuccessHandler implements LogoutSuccessHandler {

    @Value("${rpbLogOut}")
    private String rpbLogoutBaseUrl;

    @Value("${spring.security.oauth2.client.registration.custom.client-id}")
    private String clientId;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,Authentication authentication) throws IOException
    {
        try {
            // Invalidate HTTP Session (Server-side cleanup)
            if (request.getSession(false) != null) {
                request.getSession(false).invalidate();
                System.out.println("HTTP Session invalidated on server.");
            }

            // Force-delete common session cookies (Browser-side cleanup)
            System.out.println("Executing local session cleanup: Clearing JSESSIONID cookie.");
            deleteCookie(request, response, "JSESSIONID");

            // Clear Authentication Context (Spring Security Context cleanup)
            org.springframework.security.core.context.SecurityContextHolder.clearContext();

            // --- DYNAMIC KEYCLOAK LOGOUT URL CONSTRUCTION ---
            String fullLogoutUrl = buildKeycloakLogoutUrl(authentication);

            // 4. External SSO Logout Redirect
            // This redirects the browser to Keycloak to terminate the SSO session using the ID Token Hint.
            response.sendRedirect(fullLogoutUrl);

        } catch (Exception e) {
            System.err.println("Error during SSO logout or redirect: " + e.getMessage());
            // Updated fallback to use context path for robustness
            response.sendRedirect(request.getContextPath() + "/login?logout");
        }
    }

    private String buildKeycloakLogoutUrl(Authentication authentication) {
        // Start with the base URL and add mandatory parameters
        StringBuilder urlBuilder = new StringBuilder(rpbLogoutBaseUrl);

        // Extract ID Token Hint
        if (authentication instanceof OAuth2AuthenticationToken) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            String idToken = oidcUser.getIdToken().getTokenValue();

            if (idToken != null && !idToken.isEmpty()) {
                System.out.println("ID Token found. Adding id_token_hint to logout request.");
                urlBuilder.append("&id_token_hint=").append(idToken);
            }
        }

        return urlBuilder.toString();
    }

    private void deleteCookie(HttpServletRequest request, HttpServletResponse response, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieName)) {
                    Cookie expiredCookie = new Cookie(cookieName, null);
                    // Must use the same path the cookie was created with (context path ensures broad coverage)
                    expiredCookie.setPath(request.getContextPath() + "/");
                    expiredCookie.setMaxAge(0);
                    expiredCookie.setSecure(false);
                    expiredCookie.setHttpOnly(true);
                    response.addCookie(expiredCookie);
                    System.out.println("Force-removed cookie: " + cookieName);
                    return;
                }
            }
        }
    }
}