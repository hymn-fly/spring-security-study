package com.prgms.devcourse.springsecuritymasterclass.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OauthAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException
    {
        /*
        * JWT 토큰을 만들어서 응답
        * 사용자를 가입시키는 처리(이미 가입되었다면 아무 처리하지 않음)
        * */
        log.info("OAuth2 principal : {}", authentication.getPrincipal());
    }
}
