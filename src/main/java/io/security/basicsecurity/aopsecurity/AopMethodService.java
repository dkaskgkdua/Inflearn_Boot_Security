package io.security.basicsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopMethodService {
    public void methodSecured() {
        System.out.println("methodSecured");
    }

    public void methodSecuredManager() {
        System.out.println("methodSecuredManager");
    }
}
