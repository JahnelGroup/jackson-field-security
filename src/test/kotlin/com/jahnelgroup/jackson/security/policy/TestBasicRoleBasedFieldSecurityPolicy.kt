package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.principal.SpringSecurityPrincipalProvider
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.util.ReflectionUtils

@RunWith(SpringRunner::class)
class TestBasicRoleBasedFieldSecurityPolicy {

    val mockSecureField : SecureField = Mockito.mock(SecureField::class.java)
    val mockPropertyWriter = Mockito.mock(PropertyWriter::class.java)

    var policy = RoleBasedFieldSecurityPolicy(SpringSecurityPrincipalProvider())

    @SecureField val default = Any()
    @SecureField(roles = arrayOf("ONE")) val oneRole = Any()
    @SecureField(roles = arrayOf("ONE", "TWO")) val twoRoles = Any()

    //
    // Not logged in tests
    //

    @Test
    fun `Not logged - default returns false`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    fun `Not logged - one role returns false`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    fun `Not logged - two role returns false`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Logged in with no roles
    //

    @Test
    @WithMockUser(username = "user")
    fun `Logged in no roles - default returns false`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user")
    fun `Logged in no roles - one role returns false`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user")
    fun `Logged in no roles - two roles returns false`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Logged in with one role not matching
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("NOT_MATCHING"))
    fun `Logged in one role - default returns false`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("NOT_MATCHING"))
    fun `Logged in one role - one role not matching returns false`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("NOT_MATCHING"))
    fun `Logged in one role - two roles not matching returns false`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    private fun getAnnotation(name: String) = ReflectionUtils.findField(
        TestBasicRoleBasedFieldSecurityPolicy::class.java, name)
            .getAnnotation(SecureField::class.java)
}