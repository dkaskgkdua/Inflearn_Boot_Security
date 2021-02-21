package io.security.basicsecurity.aopsecurity;

import io.security.basicsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class AopSecurityController {
    private final AopMethodService aopMethodService;
    
    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #accountDto.username == principal.username")
    public String preAuthorize(AccountDto accountDto, Model model, Principal principal) {
        model.addAttribute("method", "Success @PreAuthorize");

        return "aop/method";
    }
    
    @GetMapping("/methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }
    @GetMapping("/methodSecuredManager")
    public String methodSecuredManager(Model model) {
        aopMethodService.methodSecuredManager();
        model.addAttribute("method", "Success methodSecuredManager");

        return "aop/method";
    }


    
}
