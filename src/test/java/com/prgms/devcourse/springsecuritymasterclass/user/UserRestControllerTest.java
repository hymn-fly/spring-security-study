package com.prgms.devcourse.springsecuritymasterclass.user;

import com.prgms.devcourse.springsecuritymasterclass.config.JwtConfiguration;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserRestControllerTest {

    @LocalServerPort
    int port;

    @Autowired
    private JwtConfiguration jwtConfiguration;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void JWT_토큰_테스트() {
        assertThat(tokenToName(getToken("user", "user123"))).isEqualTo("user");
        assertThat(tokenToName(getToken("admin", "admin123"))).isEqualTo("admin");
    }

    private String getToken(String username, String credential){
        URI uri =  UriComponentsBuilder.fromUriString("http://localhost:" + port)
                .path("/api/user/login")
                .encode().build().toUri();
        RequestEntity<LoginRequest> request = RequestEntity.post(uri).body(new LoginRequest(username, credential));

        UserResponse body = restTemplate.exchange(request, UserResponse.class).getBody();
        if(body == null){
            return null;
        }
        return body.getToken();
    }

    private String tokenToName(String token){
        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtConfiguration.getHeader(), token);

        UserResponse body = restTemplate.exchange(
                "/api/user/me",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                UserResponse.class
        ).getBody();
        if(body == null){
            return null;
        }
        return body.getUsername();
    }
}