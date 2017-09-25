package com.jahnelgroup.jackson.security.principal

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.core.context.SecurityContextHolder

/**
 * Autoconfiguration for [PrincipalProvider].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Configuration
@ConditionalOnClass(SecurityContextHolder::class)
class PrincipalProviderAutoConfiguration {

    /**
     * The default [PrincipalProvider] is [SpringSecurityPrincipalProvider].
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(PrincipalProvider::class)
    fun principalProvider() = SpringSecurityPrincipalProvider()

}