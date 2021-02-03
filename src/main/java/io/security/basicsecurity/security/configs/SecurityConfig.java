package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    // webIgnore 설정 - 정적 리소스 관리 : 보안필터도 안거침(비용적인 측면에서 절약)
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(userDetailsService);
        auth.authenticationProvider(authenticationProvider());
    }
    // 커스텀한 provider 빈 등록
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .csrf().disable()
               .authorizeRequests()
               .antMatchers("/","/users").permitAll()
               .antMatchers("/mypage").hasRole("USER")
               .antMatchers("/messages").hasRole("MANAGER")
               .antMatchers("/config").hasRole("ADMIN")

               .anyRequest().authenticated()

       .and()
               .formLogin()
               .loginPage("/login")
               .loginProcessingUrl("/login_proc")
               .defaultSuccessUrl("/")
               .authenticationDetailsSource(authenticationDetailsSource)
               .successHandler(customAuthenticationSuccessHandler)
               .permitAll()

       ;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    // 메모리에 임의 유저정보 - 테스트용
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        String password = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password(password)  // 패스워드 인코딩 유형 괄호에 넣음
//                .roles("USER");
//        auth.inMemoryAuthentication()
//                .withUser("manager")
//                .password(password)
//                .roles("MANAGER");
//        auth.inMemoryAuthentication()
//                .withUser("admin")
//                .password(password)
//                .roles("ADMIN");
//    }
}
