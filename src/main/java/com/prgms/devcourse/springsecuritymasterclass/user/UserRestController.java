package com.prgms.devcourse.springsecuritymasterclass.user;

import com.prgms.devcourse.springsecuritymasterclass.jwt.Jwt;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final Jwt jwt;

    private final UserService userService;

    public UserRestController(Jwt jwt, UserService userService) {
        this.jwt = jwt;
        this.userService = userService;
    }

    @GetMapping("/users/{username}/token")
    public String makeToken(@PathVariable String username){
        UserDetails userDetails = userService.loadUserByUsername(username);
        String[] roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toArray(String[]::new);
        return jwt.sign(Jwt.Claims.from(username, roles));
    }

    @GetMapping("/users/token/verify")
    public Jwt.Claims verify(@RequestHeader(value="token") String token){
        return jwt.verify(token);
    }
}
