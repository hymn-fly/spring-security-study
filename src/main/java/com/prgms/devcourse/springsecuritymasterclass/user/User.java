package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;
import java.util.Collection;
import java.util.stream.Collectors;

@Entity
@Table(name="users")
public class User extends BaseEntity implements UserDetails {

    @Column(name="login_id", length = 20)
    private String loginId;

    @Column(name="passwd", length=80)
    private String passWord;

    @ManyToOne(optional = false)
    @JoinColumn(name="group_id")
    private Group group;

    public void checkPassword(PasswordEncoder passwordEncoder, String credentials){
        if(!passwordEncoder.matches(credentials, passWord)){
            throw new IllegalArgumentException("비밀번호가 다릅니다.");
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.group.getPermissions()
                .stream().map(GroupPermission::getPermission)
                .collect(Collectors.toList());
    }

    public String[] getAuthoritiesArray() {
        return this.group.getPermissions()
                .stream().map(gp -> gp.getPermission().toString())
                .toArray(String[]::new);
    }

    public Group getGroup(){
        return group;
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
