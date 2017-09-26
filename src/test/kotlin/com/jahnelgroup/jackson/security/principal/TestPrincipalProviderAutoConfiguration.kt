package com.jahnelgroup.jackson.security.principal

import org.assertj.core.api.Assertions.*
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
class TestPrincipalProviderAutoConfiguration {

    @Test
    fun `Autoconfigured provider should be SpringSecurityPrincipalProvider`() {
        assertThat(PrincipalProviderAutoConfiguration().principalProvider())
            .isInstanceOf(SpringSecurityPrincipalProvider::class.java)
    }

}