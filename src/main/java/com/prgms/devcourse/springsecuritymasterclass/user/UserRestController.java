package com.prgms.devcourse.springsecuritymasterclass.user;

import com.prgms.devcourse.springsecuritymasterclass.jwt.JwtAuthenticationToken;
import com.prgms.devcourse.springsecuritymasterclass.jwt.JwtPrincipal;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService userService;

    public UserRestController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/me")
    public UserResponse me(@AuthenticationPrincipal JwtPrincipal principal){
        return userService.findByUsername(principal.getUsername())
                .map(user -> new UserResponse(
                        principal.getJwtToken(),
                        principal.getUsername(),
                        user.getGroup().getName())
                )
                .orElseThrow(() -> new IllegalArgumentException("Could not find user for " + principal.getUsername()));
    }


//    @GetMapping("/users/{username}/token")
//    public String makeToken(@PathVariable String username){
//        UserDetails userDetails = userService.loadUserByUsername(username);
//        String[] roles = userDetails.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority).toArray(String[]::new);
//        return jwt.sign(Jwt.Claims.from(username, roles));
//    }
//
//    @GetMapping("/users/token/verify")
//    public Jwt.Claims verify(@RequestHeader(value="token") String token){
//        return jwt.verify(token);
//    }
}
