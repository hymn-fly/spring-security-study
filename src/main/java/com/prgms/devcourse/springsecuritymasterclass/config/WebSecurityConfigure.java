package com.prgms.devcourse.springsecuritymasterclass.config;

import com.prgms.devcourse.springsecuritymasterclass.jwt.Jwt;
import com.prgms.devcourse.springsecuritymasterclass.jwt.JwtAuthenticationFilter;
import com.prgms.devcourse.springsecuritymasterclass.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;

@EnableWebSecurity
@Configuration
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserService userService;

    private final JwtConfiguration jwtConfiguration;

    public WebSecurityConfigure(UserService userService, JwtConfiguration jwtConfiguration) {
        this.userService = userService;
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /* custom UserDetailsService */
        auth.userDetailsService(userService);

        /* JdbcUserDetailsManager
        *
        auth.jdbcAuthentication().dataSource(dataSource)
                .usersByUsernameQuery("SELECT login_id, passwd, true " +
                        "FROM users " +
                        "where login_id = ?;")
                .groupAuthoritiesByUsername(
                        "SELECT g.id, g.name, p.name FROM users u " +
                                "JOIN groups g ON u.group_id=g.id " +
                                "JOIN group_permission gp ON g.id=gp.group_id " +
                                "JOIN permissions p ON gp.permission_id=p.id " +
                                "where login_id=?;"
                ).getUserDetailsService().setEnableAuthorities(false);*/


        /*
        * InMemoryUserDetailsManager
        String idForEncode = "noop";

        auth.inMemoryAuthentication()
                .withUser("user").password(format("{%s}user123", idForEncode)).roles("USER").and()
                .withUser("admin01").password(format("{%s}admin123", idForEncode)).roles("ADMIN").and()
                .withUser("admin02").password(format("{%s}admin123", idForEncode)).roles("ADMIN");*/
    }

    @Override
    public void configure(WebSecurity web){
        web.ignoring()
                .antMatchers("/assets/**", "/h2-console/**");
    }

    @Bean
    public AccessDecisionManager customAccessDecisionManager(){
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
        return new UnanimousBased(voters);
    }

    @Bean
    Jwt jwt(JwtConfiguration jwtConfiguration){
        return new Jwt(
                jwtConfiguration.getIssuer(),
                jwtConfiguration.getClientSecret(),
                jwtConfiguration.getExpirySeconds()
                );
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/api/user/me").hasAnyRole("USER", "ADMIN")
//                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                .anyRequest().permitAll()
                .accessDecisionManager(customAccessDecisionManager())
                .and()
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .headers(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(new JwtAuthenticationFilter(jwt(jwtConfiguration)))
//                .addFilterAt(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//            .formLogin()
//                .defaultSuccessUrl("/")
//                .permitAll()
//                .and()

            /* 로그아웃 설정 */
//            .logout()
//                .logoutSuccessUrl("/")
//                .and()
            /*
            *  remember me 설정
            **/
//            .rememberMe().tokenValiditySeconds(300)
//                .key("my-remember-key")
//                .rememberMeParameter("remember")
//                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
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
