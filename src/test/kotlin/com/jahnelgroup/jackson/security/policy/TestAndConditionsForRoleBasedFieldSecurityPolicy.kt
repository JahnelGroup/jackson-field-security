package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.principal.SpringSecurityPrincipalProvider
import org.assertj.core.api.Assertions
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.util.ReflectionUtils

@RunWith(SpringRunner::class)
class TestAndConditionsForRoleBasedFieldSecurityPolicy {

    val mockSecureField : SecureField = Mockito.mock(SecureField::class.java)
    val mockPropertyWriter = Mockito.mock(PropertyWriter::class.java)

    var policy = RoleBasedFieldSecurityPolicy(SpringSecurityPrincipalProvider())

    @SecureField
    val default = Any()
    @SecureField(roles = arrayOf("ONE")) val oneRole = Any()
    @SecureField(roles = arrayOf("ONE", "TWO")) val twoRoles = Any()
    @SecureField(roles = arrayOf("ONE", "TWO", "THREE")) val threeRoles = Any()

    //
    // One Role
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE"))
    fun `and matching one role returns true`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NONE"))
    fun `and not matching one role returns false`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Two Roles
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE", "ROLE_TWO"))
    fun `and matching two roles returns true`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE", "ROLE_NONE"))
    fun `and matching one of two roles returns false`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NONE"))
    fun `and matching none of two roles`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Three
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE", "ROLE_TWO", "ROLE_THREE"))
    fun `and matching three roles returns true`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("threeRoles"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE", "ROLE_TWO"))
    fun `and matching two of three roles returns false`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("threeRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_ONE"))
    fun `and matching one of three roles returns false`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("threeRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NONE"))
    fun `and matching none of three roles returns false`(){
        Assertions.assertThat(policy.permitAccess(getAnnotation("threeRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }



    private fun getAnnotation(name: String) = ReflectionUtils.findField(
        TestAndConditionsForRoleBasedFieldSecurityPolicy::class.java, name)
            .getAnnotation(SecureField::class.java)
}
