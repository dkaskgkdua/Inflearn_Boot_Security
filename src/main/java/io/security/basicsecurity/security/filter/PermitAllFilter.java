package io.security.basicsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 권한 없이 접근 가능한 리소스 필터
 * -> 비용 아낌
 */
public class PermitAllFilter extends FilterSecurityInterceptor {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

    public PermitAllFilter(String... permitAllResources) {
        for(String resource : permitAllResources) {
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {
        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for(RequestMatcher requestMatcher : permitAllRequestMatchers) {
            if(requestMatcher.matches(request)) {
                permitAll = true;
                break;
            }
        }

        if(permitAll) {
            return null;
        }

        return super.beforeInvocation(object);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if ((fi.getRequest() != null)
                && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        }
        else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null && observeOncePerRequest) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            }
            finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }

}
