package com.prgms.devcourse.springsecuritymasterclass.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import javax.servlet.http.HttpServletResponse;

import java.util.List;

import static java.lang.String.format;

@EnableWebSecurity(debug = true)
@Configuration
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String idForEncode = "noop";

        auth.inMemoryAuthentication()
                .withUser("user").password(format("{%s}user123", idForEncode)).roles("USER").and()
                .withUser("admin01").password(format("{%s}admin123", idForEncode)).roles("ADMIN").and()
                .withUser("admin02").password(format("{%s}admin123", idForEncode)).roles("ADMIN");
    }

    @Override
    public void configure(WebSecurity web){
        web.ignoring()
                .antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                .anyRequest().permitAll()
                .accessDecisionManager(new UnanimousBased(List.of(
                        new WebExpressionVoter(),
                        new OddAdminVoter())))
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/")
                .and()
            .rememberMe().tokenValiditySeconds(300)
                .key("my-remember-key")
                .rememberMeParameter("remember")
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler()).and()
//                .sessionManagement()
//                .sessionFixation().changeSessionId()
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                .invalidSessionUrl("/")
//                .maximumSessions(1)
//                    .maxSessionsPreventsLogin(false);
        ;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return (request, response, accessDeniedException) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, accessDeniedException);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };

    }


}
