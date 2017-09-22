package com.jahnelgroup.jackson.security.principal

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

/**
 * PrincipalAwareAutoConfiguration
 */
@Configuration
class PrincipalAwareAutoConfiguration {

    @Bean
    @Primary
    @ConditionalOnMissingBean(SpringSecurityPrincipalAware::class)
    fun principalAware() = SpringSecurityPrincipalAware()

}