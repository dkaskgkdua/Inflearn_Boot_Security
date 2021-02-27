package io.security.basicsecurity.controller;

import io.security.basicsecurity.domain.dto.AccountDto;
import io.security.basicsecurity.domain.dto.TokenDto;
import io.security.basicsecurity.domain.entity.Account;
import io.security.basicsecurity.security.filter.JwtFilter;
import io.security.basicsecurity.security.provider.JwtTokenProvider;
import io.security.basicsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;

@RestController
@RequestMapping("/v1/api")
@RequiredArgsConstructor
public class JwtController {
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;


    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }

    @GetMapping("/accounts/{id}")
    public ResponseEntity<Account> retrieveAccount(@PathVariable Long id) {
        AccountDto user = userService.getUser(id);
        ModelMapper modelmapper = new ModelMapper();
        Account account = modelmapper.map(user, Account.class);

        return ResponseEntity.ok(account);
    }

    @PostMapping("/accounts")
    public ResponseEntity<Account> signup(@Valid @RequestBody AccountDto accountDto) {
        ModelMapper modelmapper = new ModelMapper();
        Account account = modelmapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));

        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(account.getId())
                .toUri();

        return ResponseEntity.created(location)
                .build().ok(userService.createUser(account));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody AccountDto accountDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        Authentication authenticate =
                authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        // 인증정보를 기반으로 토큰정보 가져옴
        String jwt = jwtTokenProvider.createToken(authenticate);

        // 토큰 정보를 헤더에 넣어줌
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        // Dto 활용해서 Body에도 넣어줌줌
       return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }

}
