package com.prgms.devcourse.springsecuritymasterclass.jwt;

import com.prgms.devcourse.springsecuritymasterclass.user.User;
import com.prgms.devcourse.springsecuritymasterclass.user.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final Jwt jwt;

    private final UserService userService;

    public JwtAuthenticationProvider(Jwt jwt, UserService userService) {
        this.jwt = jwt;
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;

        return processUserAuthentication(
                (String) jwtAuthenticationToken.getPrincipal(),
                jwtAuthenticationToken.getCredentials());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Authentication processUserAuthentication(String username, String credentials){
        try{
            User loginUser = userService.login(username, credentials);

            Jwt.Claims claims = Jwt.Claims.from(loginUser.getUsername(), loginUser.getAuthoritiesArray());
            String token = jwt.sign(claims);

            return new JwtAuthenticationToken(
                    new JwtPrincipal(username, token),
                    null,
                    loginUser.getAuthorities());
        }
        catch (IllegalArgumentException e){
            throw new BadCredentialsException(e.getMessage());
        }
        catch (Exception e){
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }
}
