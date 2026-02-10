package com.suraj.enterpriseauthenticationsystem.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * THE TRANSLATOR:
 * Maps scopes from the JWT (e.g. "email", "profile") into Spring Authorities.
 */
public class CustomJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Extracts the standard scopes (e.g., SCOPE_read, SCOPE_write)
        var defaultConverter = new JwtGrantedAuthoritiesConverter();
        var authorities = defaultConverter.convert(jwt);

        // This makes the JWT available to your @RestController logic
        return new JwtAuthenticationToken(jwt, authorities);
    }
}