package io.security.basicsecurity.security.factory;

import io.security.basicsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

public class MethodResourcesFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {
    private SecurityResourceService securityResourceService;
    private LinkedHashMap<String, List<ConfigAttribute>> resourcesMap;

    private String resourceType;

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }
    // 여기서 만든 객체가 Bean이 됨.
    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {

        if(resourcesMap == null) {
            init();
        }
        return resourcesMap;
    }

    private void init() {
        if ("method".equals(resourceType)) {
            resourcesMap = securityResourceService.getMethodResourceList();
        }else if("pointcut".equals(resourceType)){
            resourcesMap = securityResourceService.getPointcutResourceList();
        }
    }


    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    // 싱글톤 적용. 메모리에 하나만.
    @Override
    public boolean isSingleton() {
        return true;
    }
}
