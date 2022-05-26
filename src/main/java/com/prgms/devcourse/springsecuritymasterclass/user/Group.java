package com.prgms.devcourse.springsecuritymasterclass.user;

import lombok.Getter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="groups")
@Getter
public class Group extends BaseEntity{

    private String name;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "group")
    private List<GroupPermission> permissions = new ArrayList<>();
}
