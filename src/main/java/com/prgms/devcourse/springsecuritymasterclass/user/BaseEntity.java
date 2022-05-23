package com.prgms.devcourse.springsecuritymasterclass.user;

import lombok.Getter;

import javax.persistence.Id;
import javax.persistence.MappedSuperclass;
import java.io.Serializable;

@MappedSuperclass
@Getter
abstract class BaseEntity implements Serializable {
    @Id
    private Long id;
}
