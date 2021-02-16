package io.security.basicsecurity.security.metadatasource;

import io.security.basicsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * url 기반 웹 인가처리
 * 기존 config 에서 .antMatchers("/mypage").hasRole("USER") 를 사용하던 것을
 * 별도로 분리해서 설정
 * 기존 필터 앞에 필터를 둬서 먼저 처리를 하는데
 * 시큐리티의 경우 먼저 처리를 한 경우 뒤에 필터가 추가로 처리를 안함
 * -> FilterSecurityInterceptor
 * 즉 위에 기존 config 설정한 matchers 가 무용지물(?)이 됨
 */
@Slf4j
public class UrlFilterInvocationSecurityMetadatsSource implements FilterInvocationSecurityMetadataSource {
    // map<url ,권한정보 리스트> 형태
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;

    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadatsSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap
                        , SecurityResourceService securityResourceService) {
        this.requestMap = requestMap;
        this.securityResourceService = securityResourceService;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        //requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));

        if(requestMap != null){
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)){
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * db에 있는 정보가 실시간으로 반영되게 reload 메서드 생성
     */
    public void reload() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        requestMap.clear();

        while(iterator.hasNext()) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
}