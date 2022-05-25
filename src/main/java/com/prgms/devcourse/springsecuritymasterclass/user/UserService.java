package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService{
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public User login(String username, String credentials){
        User user = userRepository.findByLoginId(username).orElseThrow(() -> new UsernameNotFoundException("Could not find user for " + username));
        user.checkPassword(passwordEncoder, credentials);

        return user;
    }



}
