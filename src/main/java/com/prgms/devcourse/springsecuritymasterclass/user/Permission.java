package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="permissions")
class Permission extends BaseEntity implements GrantedAuthority {

    @Column(length = 20)
    private String name;

    @Override
    public String getAuthority() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}
