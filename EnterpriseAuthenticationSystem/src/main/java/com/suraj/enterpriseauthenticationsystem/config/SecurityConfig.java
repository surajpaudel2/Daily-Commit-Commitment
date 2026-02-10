package com.suraj.enterpriseauthenticationsystem.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                /* * 1. DISABLE CSRF:
                 * Since we are building a stateless API that uses JWTs (tokens),
                 * we don't need CSRF protection (which is for session-based cookies).
                 */
                .csrf(csrf -> csrf.disable())

                /* * 2. AUTHORIZATION RULES:
                 * This defines which URLs are public and which are locked.
                 */
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public/**").permitAll() // Allow anyone to see these
                        .anyRequest().authenticated()                  // Everything else requires a valid JWT
                )

                /* * 3. STATELESS SESSIONS:
                 * We tell Spring NOT to create a session in the database/memory.
                 * Every request must bring its own token (JWT).
                 */
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                /* * 4. OAUTH2 RESOURCE SERVER:
                 * This is the "Bouncer" logic. It tells the app to expect a
                 * Bearer Token in the header and validate it using the JWT standard.
                 */
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> {}) // Use default JWT validation settings
                );

        return http.build();
    }
}