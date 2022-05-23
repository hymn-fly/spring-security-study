package com.prgms.devcourse.springsecuritymasterclass.user;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="groups")
class Group extends BaseEntity{

    private String name;
}
