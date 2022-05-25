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

    private final AuthenticationManager authenticationManager;

    public UserRestController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
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

    @PostMapping("/user/login")
    public UserResponse login(@RequestBody LoginRequest request){
        User user = userService.login(request.user, request.password);
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(request.user, request.password);

        Authentication resultToken = authenticationManager.authenticate(authenticationToken);
        JwtPrincipal principal = (JwtPrincipal)resultToken.getPrincipal();
        return new UserResponse(principal.getJwtToken(), user.getUsername(), user.getGroup().getName());
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
