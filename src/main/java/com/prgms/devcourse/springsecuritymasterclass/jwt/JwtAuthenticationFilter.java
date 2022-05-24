package com.prgms.devcourse.springsecuritymasterclass.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final Jwt jwt;

    public JwtAuthenticationFilter(Jwt jwt) {
        this.jwt = jwt;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = getToken((HttpServletRequest) request);
        if(token == null){
            chain.doFilter(request, response);
            return;
        }

        Jwt.Claims claims = jwt.verify(token);

        String username = claims.getUsername();
        List<GrantedAuthority> authorities = Arrays.stream(claims.roles)
                .map(SimpleGrantedAuthority::new).collect(Collectors.toUnmodifiableList());

        UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(
                username, null, authorities);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(userToken);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest request){
        return request.getHeader("token");
    }
}
