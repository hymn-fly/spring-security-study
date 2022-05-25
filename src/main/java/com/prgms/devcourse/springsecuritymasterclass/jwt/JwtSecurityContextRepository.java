package com.prgms.devcourse.springsecuritymasterclass.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class JwtSecurityContextRepository implements SecurityContextRepository {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final String headerKey;

    private final Jwt jwt;

    public JwtSecurityContextRepository(String headerKey, Jwt jwt) {
        this.headerKey = headerKey;
        this.jwt = jwt;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        Authentication jwtToken = authenticate(request);
        SecurityContext context = SecurityContextHolder.getContext();
        if(jwtToken != null){
            context.setAuthentication(jwtToken);
        }
        return context;
    }

    private JwtAuthenticationToken authenticate(HttpServletRequest request){
        String token = getToken(request);
        if(!StringUtils.hasText(token)){
            return null;
        }

        try{
            Jwt.Claims claims = jwt.verify(token);

            String username = claims.getUsername();
            List<GrantedAuthority> authorities = getAuthorities(claims);

            if (StringUtils.hasText(username) && authorities != null && !authorities.isEmpty()){
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                        new JwtPrincipal(username, token),
                        null,
                        authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                return authentication;
            }

        }
        catch (JWTVerificationException e){
            log.warn("Jwt processing failed : {}", e.getMessage());
        }
        return null;


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

        return (roles == null || roles.length == 0)
                ? Collections.emptyList()
                :Arrays.stream(roles).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableList());
    }


    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        /* no operation */
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return authenticate(request) != null;
    }
}
