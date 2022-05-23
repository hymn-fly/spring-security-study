package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.boot.context.properties.EnableConfigurationProperties;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name="group_permission")
class GroupPermission extends BaseEntity{

    @Column(name="group_id")
    private Long groupId;

    @Column(name="permission_id")
    private Long permissionId;

}
