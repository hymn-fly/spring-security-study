package com.prgms.devcourse.springsecuritymasterclass.user;

import lombok.Getter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import javax.persistence.*;

@Entity
@Table(name="group_permission")
@Getter
class GroupPermission extends BaseEntity{

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="group_id")
    private Group group;

    @ManyToOne
    @JoinColumn(name="permission_id")
    private Permission permission;

}
