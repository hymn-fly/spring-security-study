package com.prgms.devcourse.springsecuritymasterclass.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@EnableWebSecurity
@Configuration
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String idForEncode = "noOp";
        Map<String,PasswordEncoder> encoders = new HashMap<>();
        encoders.put(idForEncode, NoOpPasswordEncoder.getInstance());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());

        auth.inMemoryAuthentication()
                .passwordEncoder(new DelegatingPasswordEncoder("noop", encoders))
                .withUser("user").password("user123").roles("USER").and()
                .withUser("admin").password("admin123").roles("ADMIN");
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
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .defaultSuccessUrl("/")
                .permitAll();
    }
}
