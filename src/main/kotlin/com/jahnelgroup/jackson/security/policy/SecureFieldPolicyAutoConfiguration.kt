package com.jahnelgroup.jackson.security.policy

import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * Autoconfiguration for default policy beans.
 *
 * @author Steven Zgaljic
 * @since 1.0.3
 */
@Configuration
class SecureFieldPolicyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = arrayOf("createdByFieldSecurityPolicy") )
    fun createdByFieldSecurityPolicy() =
        CreatedByFieldSecurityPolicy()

    @Bean
    @ConditionalOnMissingBean(name = arrayOf("roleBasedFieldSecurityPolicy") )
    fun roleBasedFieldSecurityPolicy(principalProvider: PrincipalProvider) =
        RoleBasedFieldSecurityPolicy(principalProvider)

}