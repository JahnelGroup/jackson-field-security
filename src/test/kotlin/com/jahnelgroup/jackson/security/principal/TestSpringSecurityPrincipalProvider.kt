package com.jahnelgroup.jackson.security.principal

import org.assertj.core.api.Assertions.*
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
class TestSpringSecurityPrincipalProvider {

    var provider = SpringSecurityPrincipalProvider()

    @Test
    fun `Returns null principal when not logged in`(){
        assertThat(provider.getPrincipal()).isNull()
    }

    @Test
    fun `Returns null roles when not logged in`(){
        assertThat(provider.getRoles()).isNull()
    }

    @Test
    @WithMockUser(username = "admin", authorities = arrayOf("USER", "ADMIN"))
    fun `Returns the principal when logged in`(){
        assertThat(provider.getPrincipal()).isEqualTo("admin")
    }

    @Test
    @WithMockUser(username = "admin", authorities = arrayOf("USER", "ADMIN"))
    fun `Returns the roles when logged in`(){
        assertThat(provider.getRoles()).containsExactlyInAnyOrder("USER", "ADMIN")
    }

}