package com.suraj.enterpriseauthenticationsystem.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Test Controller for OAuth2 + OIDC Authentication
 *
 * PURPOSE:
 * --------
 * This controller demonstrates different ways to access authenticated user information
 * and shows how Spring Security handles both session-based (OIDC) and stateless (JWT) auth.
 *
 * ENDPOINTS EXPLAINED:
 * --------------------
 * 1. /public   → Anyone can access (no login required)
 * 2. /user     → Requires authentication (any logged-in user)
 * 3. /admin    → Requires ROLE_admin (we'll add this security later)
 * 4. /user/info → Shows detailed user info from OIDC
 * 5. /api/secure → Accepts JWT in Authorization header (stateless)
 *
 * @author Suraj
 */
@RestController
public class TestController {

    // ========================================================================
    // PUBLIC ENDPOINT - No Authentication Required
    // ========================================================================

    /**
     * Public endpoint accessible to everyone.
     *
     * USE CASE: Landing pages, health checks, public APIs
     *
     * SECURITY: No security applied (we'll configure this in SecurityConfig)
     *
     * @return Public message
     */
    @GetMapping("/public")
    public Map<String, Object> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a PUBLIC endpoint - no login required");
        response.put("timestamp", System.currentTimeMillis());
        response.put("accessible_by", "Everyone (anonymous users)");

        return response;
    }


    // ========================================================================
    // USER ENDPOINT - Requires Authentication (Any Logged-In User)
    // ========================================================================

    /**
     * Protected endpoint requiring authentication.
     *
     * HOW IT WORKS:
     * -------------
     * 1. User must complete OIDC login flow first
     * 2. Spring Security checks if user is authenticated
     * 3. If authenticated → Allow access
     * 4. If not authenticated → Redirect to Keycloak login
     *
     * @param authentication Spring Security's Authentication object
     *                       (automatically injected if user is logged in)
     * @return User information
     */
    @GetMapping("/user")
    public Map<String, Object> userEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        // Authentication object contains:
        // - principal: The logged-in user's identity (username, email, etc.)
        // - authorities: The user's roles/permissions
        // - credentials: Usually null after authentication (password not stored)
        // - authenticated: true/false

        response.put("message", "Welcome, authenticated user!");
        response.put("username", authentication.getName());  // Usually the username or email
        response.put("authenticated", authentication.isAuthenticated());

        // Extract roles/authorities
        // Spring Security stores roles as "ROLE_admin", "ROLE_user", etc.
        response.put("authorities", authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // The principal object type depends on the authentication method:
        // - OIDC Login: OidcUser
        // - JWT: Jwt
        // - Form Login: UserDetails
        response.put("principal_type", authentication.getPrincipal().getClass().getSimpleName());

        return response;
    }


    // ========================================================================
    // ADMIN ENDPOINT - Requires ROLE_admin
    // ========================================================================

    /**
     * Admin-only endpoint.
     *
     * AUTHORIZATION vs AUTHENTICATION:
     * --------------------------------
     * AUTHENTICATION = "Who are you?" (handled by login)
     * AUTHORIZATION = "What can you do?" (handled by roles/permissions)
     *
     * This endpoint requires:
     * 1. User must be authenticated (logged in)
     * 2. User must have ROLE_admin authority
     *
     * We'll configure this restriction in SecurityConfig using:
     * .requestMatchers("/admin").hasRole("admin")
     *
     * @param authentication The authenticated user
     * @return Admin dashboard data
     */
    @GetMapping("/admin")
    public Map<String, Object> adminEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        response.put("message", "Welcome to ADMIN dashboard!");
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        response.put("access_level", "ADMIN");

        return response;
    }


    // ========================================================================
    // USER INFO ENDPOINT - Shows OIDC User Details
    // ========================================================================

    /**
     * Displays detailed OIDC user information from ID Token.
     *
     * WHAT IS OidcUser?
     * -----------------
     * After OIDC login, Spring Security creates an OidcUser object containing:
     * - ID Token claims (sub, email, name, etc.)
     * - User attributes from Keycloak
     * - Access token (for making API calls to other services)
     *
     * @param oidcUser Automatically injected by Spring Security
     *                 (only works for OIDC-authenticated users)
     * @return Detailed user information
     */
    @GetMapping("/user/info")
    public Map<String, Object> userInfo(@AuthenticationPrincipal OidcUser oidcUser) {
        Map<String, Object> response = new HashMap<>();

        // Basic user info
        response.put("username", oidcUser.getPreferredUsername());
        response.put("email", oidcUser.getEmail());
        response.put("full_name", oidcUser.getFullName());
        response.put("email_verified", oidcUser.getEmailVerified());

        // Subject (unique user ID in Keycloak)
        response.put("subject", oidcUser.getSubject());

        // ID Token claims (all claims from the JWT ID token)
        response.put("id_token_claims", oidcUser.getClaims());

        // Authorities/Roles
        response.put("authorities", oidcUser.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // Access Token (you can use this to call other protected APIs)
        // Note: This returns the token itself, be careful about exposing it
        response.put("access_token_present", oidcUser.getIdToken() != null);

        return response;
    }


    // ========================================================================
    // STATELESS API ENDPOINT - Accepts JWT in Authorization Header
    // ========================================================================

    /**
     * Stateless API endpoint that validates JWT tokens.
     *
     * USE CASE:
     * ---------
     * This is for APIs consumed by:
     * - Mobile apps
     * - Single Page Applications (React, Angular, Vue)
     * - Server-to-server communication
     *
     * HOW IT WORKS:
     * -------------
     * 1. Client sends JWT in Authorization header:
     *    Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
     *
     * 2. Spring Security's OAuth2ResourceServer validates:
     *    - JWT signature (using Keycloak's public key)
     *    - Expiry time (exp claim)
     *    - Issuer (iss claim must match issuer-uri)
     *    - Not before time (nbf claim)
     *
     * 3. If valid → Extracts claims and creates Authentication
     *    If invalid → Returns 401 Unauthorized
     *
     * DIFFERENCE FROM /user ENDPOINT:
     * -------------------------------
     * /user → Uses session cookies (JSESSIONID)
     * /api/secure → Uses JWT in Authorization header (stateless)
     *
     * @param jwt The validated JWT token (automatically injected)
     * @return API response with token information
     */
    @GetMapping("/api/secure")
    public Map<String, Object> secureApi(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();

        response.put("message", "This is a STATELESS secured API endpoint");

        // JWT Subject (usually the username or user ID)
        response.put("subject", jwt.getSubject());

        // Token metadata
        response.put("token_id", jwt.getId());
        response.put("issuer", jwt.getIssuer().toString());
        response.put("issued_at", jwt.getIssuedAt());
        response.put("expires_at", jwt.getExpiresAt());

        // All JWT claims
        response.put("all_claims", jwt.getClaims());

        // Audience (who this token is intended for)
        response.put("audience", jwt.getAudience());

        // Custom claims (e.g., roles from Keycloak)
        // We'll properly map these in CustomJwtConverter
        response.put("realm_access", jwt.getClaim("realm_access"));

        return response;
    }


    // ========================================================================
    // HOME ENDPOINT - Shows Different Info Based on Auth Method
    // ========================================================================

    /**
     * Smart endpoint that adapts based on authentication method.
     *
     * DEMONSTRATES:
     * -------------
     * How to handle both OIDC (session-based) and JWT (stateless) auth
     * in the same endpoint.
     *
     * @param authentication The current authentication (if any)
     * @return Different response based on auth type
     */
    @GetMapping("/")
    public Map<String, Object> home(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication == null) {
            // Not authenticated
            response.put("status", "anonymous");
            response.put("message", "You are not logged in");
            response.put("login_url", "/oauth2/authorization/keycloak");

        } else if (authentication.getPrincipal() instanceof OidcUser) {
            // OIDC Authentication (session-based)
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            response.put("status", "authenticated_oidc");
            response.put("auth_type", "Session-based (OIDC)");
            response.put("username", oidcUser.getPreferredUsername());
            response.put("email", oidcUser.getEmail());

        } else if (authentication.getPrincipal() instanceof Jwt) {
            // JWT Authentication (stateless)
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("status", "authenticated_jwt");
            response.put("auth_type", "Stateless (JWT)");
            response.put("subject", jwt.getSubject());
            response.put("token_expires_at", jwt.getExpiresAt());

        } else {
            // Other authentication type
            response.put("status", "authenticated_other");
            response.put("auth_type", authentication.getClass().getSimpleName());
            response.put("username", authentication.getName());
        }

        if (authentication != null) {
            response.put("authorities", authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));
        }

        return response;
    }
}