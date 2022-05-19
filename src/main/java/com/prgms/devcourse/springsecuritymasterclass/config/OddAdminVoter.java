package com.prgms.devcourse.springsecuritymasterclass.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OddAdminVoter implements AccessDecisionVoter<FilterInvocation> {
    private static final Pattern PATTERN = Pattern.compile("[0-9]$");

    private final RequestMatcher requestMatcher;

    public OddAdminVoter(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation object, Collection<ConfigAttribute> attributes) {
        if(!requiresAuthorization(object.getRequest()))
            return ACCESS_GRANTED;
        User user = (User)authentication.getPrincipal();
        String username = user.getUsername();
        Matcher matcher = PATTERN.matcher(username);
        if(matcher.find()){
            int number = Integer.parseInt(matcher.group());
            if(number % 2 != 0){
                return ACCESS_GRANTED;
            }
            return ACCESS_DENIED;
        }
        return ACCESS_ABSTAIN;
    }

    private boolean requiresAuthorization(HttpServletRequest request){
        return requestMatcher.matches(request);
    }
}
