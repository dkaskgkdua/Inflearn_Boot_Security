package io.security.basicsecurity.security.service;

import io.security.basicsecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * Account 는 Entity 클래스로서 일반 객체와 분리해서 사용하기 위해
 * AccountContext 생성
 */
public class AccountContext extends User {
    private final Account account;
    // 생성 시 account와 권한정보 받아옴
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
