package com.jahnelgroup.jackson.security.entity

import org.assertj.core.api.Assertions.*
import org.junit.runner.RunWith
import org.junit.Test
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
class TestEntityCreatedByProviderAutoConfiguration{

    @Test
    fun `Autoconfigured provider should be SpringDataEntityCreatedByProvider`() {
        assertThat(EntityCreatedByProviderAutoConfiguration().entityCreatedByProvider())
            .isInstanceOf(SpringDataEntityCreatedByProvider::class.java)
    }

}