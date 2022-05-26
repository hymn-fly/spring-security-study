package com.prgms.devcourse.springsecuritymasterclass.oauth;

import com.prgms.devcourse.springsecuritymasterclass.jwt.Jwt;
import com.prgms.devcourse.springsecuritymasterclass.user.User;
import com.prgms.devcourse.springsecuritymasterclass.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
        if(authentication instanceof OAuth2AuthenticationToken authToken){
            User user = userService.signUp(
                    authToken.getPrincipal(),
                    authToken.getAuthorizedClientRegistrationId()
            );
            String token = generateToken(user);
            String jsonResponse = makeResponse(token, user);
            response.setContentType("application/json;charset=utf-8;");
            response.setContentLength(jsonResponse.getBytes(StandardCharsets.UTF_8).length);
            response.getWriter().write(jsonResponse);
        }

        log.info("OAuth2 principal : {}", authentication.getPrincipal());
    }

    private String generateToken(User user){
        return jwt.sign(Jwt.Claims.from(user.getUsername(), new String[]{"ROLE_USER"}));
    }

    private String makeResponse(String token, User user){
        return String.format("{\"token\": %s, \"username\": %s, \"group\" : %s}", token, user.getUsername(), user.getGroup().getName());
    }
}
