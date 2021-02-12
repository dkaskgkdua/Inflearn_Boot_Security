package io.security.basicsecurity.repository;

import io.security.basicsecurity.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
    int countByUsername(String username);
    Account findByUsername(String username);
}
