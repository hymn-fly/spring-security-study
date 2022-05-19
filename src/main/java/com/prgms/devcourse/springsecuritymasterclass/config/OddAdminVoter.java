package com.prgms.devcourse.springsecuritymasterclass.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebExpressionConfigAttribute;

import java.util.Collection;

public class OddAdminVoter implements AccessDecisionVoter<FilterInvocation> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof WebExpressionConfigAttribute;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation object, Collection<ConfigAttribute> attributes) {
        return 0;
    }
}
