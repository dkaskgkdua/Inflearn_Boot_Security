package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.basicsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.basicsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadatsSource;
import io.security.basicsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final FormWebAuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler customAuthenticationFailureHandler;
    private final PasswordEncoder passwordEncoder;

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

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // 커스텀한 provider 빈 등록
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .csrf().disable()
               .authorizeRequests()
               .antMatchers("/","/users", "user/login/**","/login*").permitAll()
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
               .failureHandler(customAuthenticationFailureHandler)
               .permitAll()
       .and()
               .exceptionHandling()
               .accessDeniedHandler(accessDeniedHandler())
        .and()
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)

       ;


    }



    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }

    /**
     * 필터 셋팅
     *
     */
    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {

        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        return filterSecurityInterceptor;
    }

    /**
     * 등록된 voter 클래스 객체 중 단 하나라도 접근 허가로 결론을 내면 최종적으로 접근 허가
     *
     * 그 외
     * - UnanimousBased : 만장일치
     * - ConsensusBased : 다수결
     */
    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
        return Arrays.asList(new RoleVoter());
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        return new UrlFilterInvocationSecurityMetadatsSource();
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
