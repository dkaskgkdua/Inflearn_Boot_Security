package io.security.basicsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // webIgnore 설정 - 정적 리소스 관리 : 보안필터도 안거침(비용적인 측면에서 절약)
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    // 메모리에 임의 유저정보 - 테스트용
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String password = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication()
                .withUser("user")
                .password(password)  // 패스워드 인코딩 유형 괄호에 넣음
                .roles("USER");
        auth.inMemoryAuthentication()
                .withUser("manager")
                .password(password)
                .roles("MANAGER");
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(password)
                .roles("ADMIN");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .authorizeRequests()
               .antMatchers("/","/users").permitAll()
               .antMatchers("/mypage").hasRole("USER")
               .antMatchers("/messages").hasRole("MANAGER")
               .antMatchers("/config").hasRole("ADMIN")

               .anyRequest().authenticated()

       .and()
               .formLogin()


       ;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
