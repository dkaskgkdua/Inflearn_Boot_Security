package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


//@Configuration
//@Order(1)       // config 인식 순서. /admin/multi 에만 따로 config를 주고 나머지 /admin/**
                // 에는 일괄권한을 주고싶다면 multi에 order를 먼저 주고 일괄에 후순위로 줘야함
                // 즉 구체적인건 우선순위가 높고, 넓은 범위는 우선순위가 낮음
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //@Autowired
    UserDetailsService userDetailsService;

    // 메모리에 임의 유저정보 - 테스트용
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}1111")  // 패스워드 인코딩 유형 괄호에 넣음
                .roles("USER");
        auth.inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111")
                .roles("SYS","USER");
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111")
                .roles("ADMIN","SYS","USER");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        // 인가정책
        http
                .csrf()
        .and()
                .authorizeRequests()            // 요청에 대한 보안검사
                .antMatchers("login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") // ADMIN만 pay 접근 가능(SYS도 불가능)
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()  // 모든 요청에도 인증을 받도록함.
        // 인증정책
        .and()
                .formLogin()                   // form 로그인 방식
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 인증 전에 요청했던 정보를 캐시로 보관했다가 인증 성공 후 요청했던 곳으로 보냄
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect(redirectUrl);
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
        .and()
                .logout()           // 기본적(원칙)으로 post방식임
                .logoutUrl("/logout")
                .logoutSuccessUrl("login") // logoutSuccessHandler로 더욱 커스텀 가능
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")  //  로그아웃할때 쿠키 삭제됨
                /**
                 *  JSESSIONID를 삭제해도
                 *  remember-me 쿠키 값이 있으면
                 *  시큐리티에서 체크하고 인증처리를 함.
                 *  -> 로그인이 된다는 말임
                 */
        .and()
                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    // 인증예외 시 처리
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");    // 세팅 시 커스텀한 login 페이지로 감
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    // 인가 예외
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })


        .and()
                .rememberMe()
                .rememberMeParameter("remember-me")         // default는 remember-me -> 커스텀 가능(체크박스와 이름 동일하게)
                .tokenValiditySeconds(5000)                 // default는 14일, 현재 5000초 설정해놨음
                .alwaysRemember(false)                       // default false, 기능이 활성화되지 않아도 항상 실행여부
                .userDetailsService(userDetailsService)    // 확인해주는 클래스 넣어줌
        .and()
                .sessionManagement()
                .sessionFixation()          // 세션 고정 보호
                .changeSessionId()          // 세션 고정 보호 정책
                .maximumSessions(1)         // 최대 세션 동시접속 수
                .maxSessionsPreventsLogin(false)  // 동시 로그인 차단함, false : 기존 세션만료(default)



        ;
        // 쓰레드 간 같은 SecurityContextHolder 정보를 공유하게 세팅
        // 모드는 총 3가지
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}

//@EnableWebSecurity
//@Order(0)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .antMatcher("/admin/multi")
                .authorizeRequests()
                .anyRequest().permitAll()
        .and()
                .httpBasic();
    }
}
