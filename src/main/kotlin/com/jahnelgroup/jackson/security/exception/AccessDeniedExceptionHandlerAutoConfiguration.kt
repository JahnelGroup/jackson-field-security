package com.jahnelgroup.jackson.security.exception

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.access.AccessDeniedException

/**
 * Autoconfiguration for [AccessDeniedExceptionHandler].
 *
 * @author Steven Zgaljic
 * @since 1.0.3
 */
@Configuration
@ConditionalOnClass(AccessDeniedException::class)
class AccessDeniedExceptionHandlerAutoConfiguration{

    /**
     * If Spring Security is on the classpath then we can use it's
     * [AccessDeniedException] to determine if the error is related
     * to security.
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(AccessDeniedExceptionHandler::class)
    fun accessDeniedExceptionHandler() = SpringSecurityAccessDeniedExceptionHandler()


}