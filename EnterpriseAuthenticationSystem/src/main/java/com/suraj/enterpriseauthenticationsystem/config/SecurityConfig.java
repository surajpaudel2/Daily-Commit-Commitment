package com.suraj.enterpriseauthenticationsystem.config;

import com.suraj.enterpriseauthenticationsystem.converter.CustomJwtConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * ============================================================================
 * ENTERPRISE SECURITY CONFIGURATION
 * ============================================================================
 *
 * This class is the BRAIN of the entire authentication system.
 * It configures Spring Security to use OAuth 2.1 + OIDC for authentication.
 *
 * ARCHITECTURE OVERVIEW:
 * ----------------------
 * This configuration implements a "Hybrid" security model:
 *
 * 1. OAUTH2 LOGIN (oauth2Login):
 *    - Handles browser-based OIDC authentication flow
 *    - Used when user clicks "Login" and goes through Keycloak
 *    - PKCE is automatically enabled (OAuth 2.1 compliance)
 *    - Creates a session with JSESSIONID cookie
 *
 * 2. RESOURCE SERVER (oauth2ResourceServer):
 *    - Validates JWT tokens on every API request
 *    - Stateless - no session required
 *    - Used for API calls from frontend (React, mobile apps)
 *    - Extracts roles from JWT and maps to Spring Security authorities
 *
 * SECURITY PRINCIPLES APPLIED:
 * ----------------------------
 * - Zero Trust: Every request must prove identity
 * - Defense in Depth: Multiple security layers
 * - Principle of Least Privilege: Users only get what they need
 * - Stateless API: JWT validation without server-side sessions
 *
 * @author Suraj
 * @version 1.0.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    /**
     * ========================================================================
     * MAIN SECURITY FILTER CHAIN
     * ========================================================================
     *
     * This is the central configuration bean that defines:
     * - Which endpoints require authentication
     * - How authentication should happen (OAuth2 Login + JWT)
     * - Security headers and protections
     * - CORS configuration
     *
     * FILTER CHAIN CONCEPT:
     * ---------------------
     * Think of this as a series of security checkpoints:
     *
     * Incoming Request
     *     ↓
     * [CORS Filter] → Check if request is from allowed origin
     *     ↓
     * [CSRF Protection] → Verify request is not forged (disabled for stateless APIs)
     *     ↓
     * [Authorization Filter] → Check if endpoint requires authentication
     *     ↓
     * [OAuth2 Login Filter] → Handle OIDC login if needed
     *     ↓
     * [JWT Validation Filter] → Validate JWT token if present
     *     ↓
     * [Role Check] → Verify user has required role
     *     ↓
     * Controller Endpoint → Your API logic
     *
     * @param http HttpSecurity object to configure
     * @return Configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ================================================================
                // CORS CONFIGURATION
                // ================================================================
                // CORS (Cross-Origin Resource Sharing) allows your React app
                // (running on localhost:3000) to make requests to your API
                // (running on localhost:8080)
                //
                // Without CORS, browsers block cross-origin requests for security.
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // ================================================================
                // CSRF PROTECTION (Disabled for Stateless APIs)
                // ================================================================
                // CSRF (Cross-Site Request Forgery) protection is important for
                // traditional form-based web apps with sessions.
                //
                // We DISABLE it here because:
                // 1. Our API is stateless (uses JWT, not cookies for auth)
                // 2. JWT in Authorization header is NOT automatically sent by browser
                // 3. CSRF attacks rely on browser auto-sending cookies
                //
                // IMPORTANT: If you're using session-based auth, ENABLE CSRF!
                .csrf(csrf -> csrf.disable())

                // ================================================================
                // AUTHORIZATION RULES (URL-Based Security)
                // ================================================================
                // This defines which endpoints require what level of access.
                //
                // EVALUATION ORDER MATTERS!
                // Spring Security evaluates these rules from TOP to BOTTOM.
                // First match wins, so put specific rules before general ones.
                .authorizeHttpRequests(auth -> auth
                        // PUBLIC ENDPOINTS - No authentication required
                        // Anyone can access these, even without logging in
                        .requestMatchers("/api/public/**").permitAll()

                        // ADMIN ENDPOINTS - Requires "admin" role
                        // Only users with ROLE_admin can access these
                        // Spring Security automatically adds "ROLE_" prefix
                        .requestMatchers("/api/admin/**").hasRole("admin")

                        // USER ENDPOINTS - Requires authentication
                        // Any authenticated user can access, regardless of role
                        .requestMatchers("/api/user/**").authenticated()

                        // ALL OTHER REQUESTS - Require authentication
                        // This is a catch-all for any endpoint not explicitly configured
                        .anyRequest().authenticated()
                )

                // ================================================================
                // OAUTH2 LOGIN CONFIGURATION (OIDC Browser Flow)
                // ================================================================
                // This enables the OAuth 2.1 Authorization Code Flow with PKCE.
                //
                // WHAT HAPPENS WHEN USER CLICKS LOGIN:
                // 1. Spring Security generates code_verifier and code_challenge (PKCE)
                // 2. Redirects browser to Keycloak with code_challenge
                // 3. User logs in at Keycloak
                // 4. Keycloak redirects back with authorization code
                // 5. Spring Security exchanges code for tokens using code_verifier
                // 6. User is authenticated and session is created
                //
                // PKCE is AUTOMATICALLY ENABLED - no manual configuration needed!
                .oauth2Login(oauth2 -> oauth2
                        // Default login page: /oauth2/authorization/keycloak
                        // This is auto-generated by Spring Security

                        // After successful login, redirect to home page
                        .defaultSuccessUrl("/api/user/profile", true)

                        // If login fails, redirect to login page with error
                        .failureUrl("/login?error=true")
                )

                // ================================================================
                // RESOURCE SERVER CONFIGURATION (JWT Validation)
                // ================================================================
                // This enables JWT-based authentication for API calls.
                //
                // HOW IT WORKS:
                // 1. Client sends request with: Authorization: Bearer <JWT>
                // 2. Spring Security extracts the JWT
                // 3. Downloads Keycloak's public key (from issuer-uri)
                // 4. Validates JWT signature using public key
                // 5. Checks JWT claims (expiry, issuer, etc.)
                // 6. Extracts roles and converts to Spring Security authorities
                // 7. If valid → User is authenticated
                //    If invalid → Returns 401 Unauthorized
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                // Use custom converter to extract roles from JWT
                                // Keycloak stores roles in custom claim structure
                                // We need to map them to Spring Security's GrantedAuthority
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )

                // ================================================================
                // SESSION MANAGEMENT
                // ================================================================
                // STATELESS: Don't create HTTP sessions for JWT-based requests
                // This is important for scalability and stateless API design.
                //
                // Note: oauth2Login WILL create sessions (for browser-based login)
                // But API calls using JWT won't create/require sessions.
                .sessionManagement(session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        // IF_REQUIRED: Create session only for oauth2Login flow
                        // STATELESS: Would break oauth2Login (use for pure API-only apps)
                )

                // ================================================================
                // SECURITY HEADERS (Production Hardening)
                // ================================================================
                // Add security headers to protect against common web attacks
                .headers(headers -> headers
                        // X-Frame-Options: Prevent clickjacking attacks
                        // DENY: Page cannot be displayed in iframe/frame
                        .frameOptions(frame -> frame.deny())

                        // X-Content-Type-Options: Prevent MIME sniffing
                        // Browser must respect Content-Type header
                        .contentTypeOptions(contentType -> {})

                        // X-XSS-Protection: Enable browser's XSS filter
                        .xssProtection(xss -> {})

                        // Content-Security-Policy: Prevent XSS and injection attacks
                        // This is a basic policy - customize for your needs
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
                        )
                );

        return http.build();
    }

    /**
     * ========================================================================
     * JWT AUTHENTICATION CONVERTER
     * ========================================================================
     *
     * This bean converts JWT claims to Spring Security authorities.
     *
     * PROBLEM:
     * Keycloak stores roles in JWT like this:
     * {
     *   "realm_access": {
     *     "roles": ["admin", "user"]
     *   }
     * }
     *
     * SOLUTION:
     * We need to extract those roles and convert them to:
     * - ROLE_admin
     * - ROLE_user
     *
     * Spring Security expects authorities with "ROLE_" prefix for .hasRole()
     *
     * @return Configured JwtAuthenticationConverter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        // Use custom converter to extract roles from Keycloak's JWT structure
        // We'll create this class next: CustomJwtConverter.java
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtConverter());

        return converter;
    }

    /**
     * ========================================================================
     * CORS CONFIGURATION SOURCE
     * ========================================================================
     *
     * Configures Cross-Origin Resource Sharing (CORS) to allow your
     * React frontend (localhost:3000) to call your API (localhost:8080).
     *
     * WHAT IS CORS?
     * -------------
     * Browsers implement "Same-Origin Policy" which blocks requests
     * from one origin (e.g., http://localhost:3000) to another origin
     * (e.g., http://localhost:8080).
     *
     * CORS headers tell the browser: "It's okay to allow this cross-origin request"
     *
     * SECURITY NOTE:
     * In production, replace "http://localhost:3000" with your actual
     * frontend domain (e.g., "https://yourdomain.com")
     *
     * @return CORS configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow requests from React app running on localhost:3000
        // In production, change this to your actual frontend URL
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));

        // Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // Allow all headers
        // Common headers: Authorization, Content-Type, Accept
        configuration.setAllowedHeaders(List.of("*"));

        // Allow credentials (cookies, authorization headers)
        // Required for sending JSESSIONID cookies or JWT tokens
        configuration.setAllowCredentials(true);

        // How long browser can cache CORS preflight response (in seconds)
        // 3600 seconds = 1 hour
        configuration.setMaxAge(3600L);

        // Apply CORS configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}