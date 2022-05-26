package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@Service
public class UserService{
    private final UserRepository userRepository;

    private final GroupRepository groupRepository;

    public UserService(UserRepository userRepository, GroupRepository groupRepository) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    @Transactional
    public User signUp(OAuth2User oAuth2User, String provider){
        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");

        String nickName = (String) properties.get("nickname");
        String profileImage = (String) properties.get("profile_image");
        String providerId = oAuth2User.getName();

        return userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseGet(() -> {
                    Group group = groupRepository.findByName("USER").orElseThrow(() -> new IllegalArgumentException("해당 group이 존재하지 않습니다."));
                    return userRepository.save(new User(nickName, provider, providerId, profileImage, group));
                });

        /*
        oauth2user로 부터 User를 만들어서(Group도 가져오고) 저장 후 반환
        * username - 카카오 닉네임
        * provider - provider 파라미터
        * providerId - oauth2User.getName()
        * profileImage - 카카오 인증된 사용자의 프로필 이미지를 사용
        * group - USER_GROUP group
        */
    }



}
