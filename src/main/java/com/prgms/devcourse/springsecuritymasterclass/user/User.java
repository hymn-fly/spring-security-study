package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.persistence.*;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Entity
@Table(name="users")
public class User extends BaseEntity implements UserDetails {

    @Column(name="login_id", length = 20)
    private String loginId;

    @Column(name="passwd", length=80)
    private String passWord;

    @ManyToOne
    @JoinColumn(name="group_id")
    private Group group;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.group.getPermissions()
                .stream().map(GroupPermission::getPermission)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return passWord;
    }

    @Override
    public String getUsername() {
        return loginId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true ;
    }
}
