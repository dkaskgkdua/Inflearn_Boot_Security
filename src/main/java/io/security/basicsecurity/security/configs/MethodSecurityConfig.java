package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.factory.MethodResourcesFactoryBean;
import io.security.basicsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.basicsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration{
    private final SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return mapBasedMethodSecurityMetadataSource();
    }
    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesFactoryBean().getObject());
    }
    @Bean
    public MethodResourcesFactoryBean methodResourcesFactoryBean() {
        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("method");
        return methodResourcesFactoryBean;

    }

    @Bean
    @Profile("pointcut")
    public MethodResourcesFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourcesFactoryBean methodResourcesMapFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesMapFactoryBean.setResourceType("pointcut");
        return methodResourcesMapFactoryBean;
    }


    @Bean
    @Profile("pointcut")
    public ProtectPointcutPostProcessor protectPointcutPostProcessor(){
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }

//    @Bean
//    public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(MapBasedMethodSecurityMetadataSource methodSecurityMetadataSource) {
//        CustomMethodSecurityInterceptor customMethodSecurityInterceptor =  new CustomMethodSecurityInterceptor();
//        customMethodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
//        customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
//        customMethodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
//        RunAsManager runAsManager = runAsManager();
//        if (runAsManager != null) {
//            customMethodSecurityInterceptor.setRunAsManager(runAsManager);
//        }
//
//        return customMethodSecurityInterceptor;
//    }
}
/**
 * ProtectPointcutPostProcessor 클래스가 해당 패키지 내에서만 사용가능해서 리플렉션 방식으로 접근
 * -> 아래와 같이 해도 에러남. 해당 클래스를 그대로 긁어와서 커스텀 후 빈으로 등록
 */
//    @Bean
//    BeanPostProcessor protectPointcutPostProcessor() throws Exception {
//        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
//        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
//        declaredConstructor.setAccessible(true);
//        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
//        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
//        setPointcutMap.setAccessible(true);
//        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
//
//        return (BeanPostProcessor) instance;
//    }

