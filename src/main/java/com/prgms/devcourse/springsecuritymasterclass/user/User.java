package com.prgms.devcourse.springsecuritymasterclass.user;

import javax.persistence.*;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static org.springframework.util.StringUtils.hasText;

@Entity
@Table(name="users")
public class User extends BaseEntity{

    @Column(name="username", length = 20)
    private String username;

    @Column(name="provider")
    private String provider;

    @Column(name="provider_id")
    private String providerId;

    @Column(name="profile_image")
    private String profileImage;

    @ManyToOne(optional = false)
    @JoinColumn(name="group_id")
    private Group group;

    public Group getGroup(){
        return group;
    }

    public Optional<String> getProfileImage(){
        return Optional.ofNullable(profileImage);
    }

    protected User() {/* no op */}

    public User(String username, String provider, String providerId, String profileImage, Group group){
        checkArgument(hasText(username));
        checkArgument(hasText(provider));
        checkArgument(hasText(providerId));
        checkArgument(group != null);

        this.username = username;
        this.provider = provider;
        this.providerId = providerId;
        this.profileImage = profileImage;
        this.group = group;
    }
}
