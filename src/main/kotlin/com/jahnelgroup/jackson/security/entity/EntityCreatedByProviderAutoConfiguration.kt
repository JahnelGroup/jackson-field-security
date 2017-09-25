package com.jahnelgroup.jackson.security.entity

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.data.annotation.CreatedBy

/**
 * Autoconfiguration for [EntityCreatedByProvider].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Configuration
@ConditionalOnClass(CreatedBy::class)
class EntityCreatedByProviderAutoConfiguration {

    /**
     * The default [EntityCreatedByProvider] is [SpringDataEntityCreatedByProvider].
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(EntityCreatedByProvider::class)
    fun entityCreatedByProvider() = SpringDataEntityCreatedByProvider()

}