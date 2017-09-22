package com.jahnelgroup.jackson.security.principal

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

/**
 * Autoconfiguration for [PrincipalProvider].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Configuration
class PrincipalProviderAutoConfiguration {

    /**
     * The default [PrincipalProvider] is [SpringSecurityPrincipalProvider].
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(PrincipalProvider::class)
    fun principalProvider() = SpringSecurityPrincipalProvider()

}