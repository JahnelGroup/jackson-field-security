package com.jahnelgroup.jackson.security.entity

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

/**
 * EntityCreatedByAwareAutoConfiguration
 */
@Configuration
class EntityCreatedByAwareAutoConfiguration {

    @Bean
    @Primary
    @ConditionalOnMissingBean(EntityCreatedByAware::class)
    fun entityCreatedByAware() = SpringDataEntityCreatedByAware()

}