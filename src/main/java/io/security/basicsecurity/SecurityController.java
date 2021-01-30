package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;

//@RestController
public class SecurityController {
    @GetMapping("/")
    public String index(HttpSession session) {
        /**
         * 인증정보 받는 법
         * 1. SecurityContextHolder 활용
         * 2. session에 담긴 것을 활용
         *
         * 두개는 동일한 것을 반환한다.
         **/
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        return "home";
    }
    /*
    @GetMapping("/thread")
    public String thread() {
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        // 메인 쓰레드 로컬에 ContextSecurity 정보를 저장했고
                        // 서브 쓰레드에는 저장 안했음.
                        // 시큐리티 기본 설정에선 쓰레드간 정보 공유 안함
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    }
                }
        ).start();
        return "thread";
    }
    @GetMapping("login")
    public String login() {
        return "login";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }
    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }*/
}
