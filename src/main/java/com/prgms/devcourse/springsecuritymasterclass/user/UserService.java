package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService{
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public User join(OAuth2User oAuth2User, String provider){

        /*
        oauth2user로 부터 User를 만들어서(Group도 가져오고) 저장 후 반환
        * username - 카카오 닉네임
        * provider - provider 파라미터
        * providerId - oauth2User.getName()
        * profileImage - 카카오 인증된 사용자의 프로필 이미지를 사용
        * group - USER_GROUP group*/

        return null;
    }



}
