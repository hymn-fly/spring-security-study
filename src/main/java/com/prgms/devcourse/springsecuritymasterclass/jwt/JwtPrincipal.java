package com.prgms.devcourse.springsecuritymasterclass.jwt;

import static com.google.common.base.Preconditions.checkNotNull;

public class JwtPrincipal {

    private final String username;

    private final String token;

    public JwtPrincipal(String username, String token) {
        checkNotNull(username);
        checkNotNull(token);

        this.username = username;
        this.token = token;
    }

    public String getUser() {
        return this.username;
    }

    public String getJwtToken() {
        return token;
    }
}
