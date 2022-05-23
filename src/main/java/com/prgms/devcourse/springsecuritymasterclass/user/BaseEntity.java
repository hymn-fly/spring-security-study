package com.prgms.devcourse.springsecuritymasterclass.user;

import lombok.Getter;

import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

@MappedSuperclass
@Getter
abstract class BaseEntity {
    @Id
    private Long id;
}
