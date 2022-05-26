package com.prgms.devcourse.springsecuritymasterclass.oauth;

import com.prgms.devcourse.springsecuritymasterclass.jwt.Jwt;
import com.prgms.devcourse.springsecuritymasterclass.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OauthAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserService userService;

    private final Jwt jwt;

    public OauthAuthenticationSuccessHandler(UserService userService, Jwt jwt) {
        this.userService = userService;
        this.jwt = jwt;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException
    {
        /*
        * JWT 토큰을 만들어서 응답
        * 사용자를 가입시키는 처리(이미 가입되었다면 아무 처리하지 않음)
        * */
        if(authentication instanceof OAuth2AuthenticationToken){
            userService.join(
                    (OAuth2User) authentication.getPrincipal(),
                    ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId());
        }

        log.info("OAuth2 principal : {}", authentication.getPrincipal());
    }
}
