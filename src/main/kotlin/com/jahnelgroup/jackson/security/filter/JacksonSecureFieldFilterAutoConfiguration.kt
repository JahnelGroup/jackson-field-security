package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider
import com.jahnelgroup.jackson.security.entity.EntityCreatedByProvider
import com.jahnelgroup.jackson.security.exception.AccessDeniedExceptionHandler
import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder

/**
 * Autoconfiguration for [Jackson2ObjectMapperBuilder].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(JacksonAutoConfiguration::class)
@ConditionalOnClass(ObjectMapper::class)
class JacksonSecureFieldFilterAutoConfiguration {

    /**
     * Registers a [Jackson2ObjectMapperBuilder] that will register
     * the securityFilter for processing the security annotations.
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(Jackson2ObjectMapperBuilder::class)
    fun jacksonObjectMapperBuilder(
            applicationContext: ApplicationContext,
            globalPrincipalAware: PrincipalProvider,
            globalEntityCreatedBy: EntityCreatedByProvider,
            accessDeniedExceptionHandler: AccessDeniedExceptionHandler) =

        Jackson2ObjectMapperBuilder().filters(
            SimpleFilterProvider().addFilter("securityFilter",
                    JacksonSecureFieldFilter(
                            applicationContext,
                            globalPrincipalAware,
                            globalEntityCreatedBy,
                            accessDeniedExceptionHandler))
        )

}