package com.prgms.devcourse.springsecuritymasterclass.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends GenericFilterBean {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final Jwt jwt;

    private final String headerKey;

    public JwtAuthenticationFilter(Jwt jwt, String headerKey) {
        this.jwt = jwt;
        this.headerKey = headerKey;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = getToken((HttpServletRequest) request);
        if(token == null || SecurityContextHolder.getContext().getAuthentication() != null){
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest req = (HttpServletRequest) request;

        try{
            Jwt.Claims claims = jwt.verify(token);

            String username = claims.getUsername();
            List<GrantedAuthority> authorities = getAuthorities(claims);

            if (StringUtils.hasText(username) && authorities != null && !authorities.isEmpty()){
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                        new JwtPrincipal(username, token),
                        null,
                        authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            chain.doFilter(request, response);
        }
        catch (JWTVerificationException e){
            log.warn("Jwt processing failed : {}", e.getMessage());
        }


    }

    private String getToken(HttpServletRequest request){
        String token = request.getHeader(headerKey);
        if(StringUtils.hasText(token)){
            log.debug("Jwt token detected : {}", token);
            try{
                String decode = URLDecoder.decode(token, "UTF-8");
                log.debug("URL decoded token : {}", decode);
                return decode;
            }catch(Exception e){
                log.error(e.getMessage(), e);
            }
        }
        return null;
    }

    private List<GrantedAuthority> getAuthorities(Jwt.Claims claims){
        String[] roles = claims.roles;
        return roles == null || roles.length == 0
                ? Collections.emptyList()
                : Arrays.stream(claims.roles)
                    .map(SimpleGrantedAuthority::new).collect(Collectors.toUnmodifiableList());
    }
}
