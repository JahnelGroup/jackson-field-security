package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider
import com.jahnelgroup.jackson.security.entity.EntityCreatedByAware
import com.jahnelgroup.jackson.security.entity.SpringDataEntityCreatedByAware
import com.jahnelgroup.jackson.security.principal.PrincipalAware
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder

/**
 * JacksonSecureFieldFilterAutoConfiguration
 */
@Configuration
@AutoConfigureBefore(JacksonAutoConfiguration::class)
@ConditionalOnClass(ObjectMapper::class)
class JacksonSecureFieldFilterAutoConfiguration {

    @Bean
    @Primary
    @ConditionalOnMissingBean(Jackson2ObjectMapperBuilder::class)
    fun jacksonObjectMapperBuilder(
            applicationContext: ApplicationContext,
            globalPrincipalAware: PrincipalAware,
            globalEntityCreatedBy: EntityCreatedByAware) =

        Jackson2ObjectMapperBuilder().filters(
            SimpleFilterProvider().addFilter("securityFilter",
                    JacksonSecureFieldFilter(
                            applicationContext,
                            globalPrincipalAware,
                            globalEntityCreatedBy))
        )

}