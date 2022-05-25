package com.prgms.devcourse.springsecuritymasterclass.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private final String credential;

    public JwtAuthenticationToken(String principal, String credential) {
        super(null);
        super.setAuthenticated(false);

        this.principal = principal;
        this.credential = credential;
    }

    public JwtAuthenticationToken(Object principal, String credential, Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        super.setAuthenticated(true);

        this.principal = principal;
        this.credential = credential;
    }

    @Override
    public String getCredentials() {
        return credential;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
