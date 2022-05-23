package com.prgms.devcourse.springsecuritymasterclass.user;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="permissions")
class Permission extends BaseEntity{

    @Column(length = 20)
    private String name;
}
