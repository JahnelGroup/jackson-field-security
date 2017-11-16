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

    val mockPropertyWriter = Mockito.mock(PropertyWriter::class.java)

    var policy = RoleBasedFieldSecurityPolicy(SpringSecurityPrincipalProvider())

    @SecureField val default = Any()
    @SecureField(roles = arrayOf("ONE")) val oneRole = Any()
    @SecureField(roles = arrayOf("ONE", "TWO")) val twoRoles = Any()

    //
    // Not logged in tests
    //

    @Test
    fun `Not logged with default SecureField (no roles required) should pass`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    fun `Not logged with SecureField requiring one role should deny`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    fun `Not logged with SecureField requiring two roles should deny`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Logged in with no roles
    //

    @Test
    @WithMockUser(username = "user")
    fun `Logged with no roles and default SecureField (no roles required) should pass`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user")
    fun `Logged with no roles and SecureField requiring one role should deny`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user")
    fun `Logged with no roles and SecureField requiring two roles should deny`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Logged in with one role not matching
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING"))
    fun `Logged with one role and default SecureField (no roles required) should pass`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING"))
    fun `Logged with one role and SecureField requiring one non-matching role should deny`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING"))
    fun `Logged with one role and SecureField requiring two non-matching roles should deny`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    //
    // Logged in with two roles, both non-matching
    //

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING_1", "ROLE_NOT_MATCHING_2"))
    fun `Logged with two roles and default SecureField (no roles required) should pass`(){
        assertThat(policy.permitAccess(getAnnotation("default"), mockPropertyWriter,
            Any(), "user", "user")).isTrue()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING_1", "ROLE_NOT_MATCHING_2"))
    fun `Logged with two roles and SecureField requiring one non-matching role should deny`(){
        assertThat(policy.permitAccess(getAnnotation("oneRole"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    @Test
    @WithMockUser(username = "user", authorities = arrayOf("ROLE_NOT_MATCHING_1", "ROLE_NOT_MATCHING_2"))
    fun `Logged with two roles and SecureField requiring two non-matching roles should deny`(){
        assertThat(policy.permitAccess(getAnnotation("twoRoles"), mockPropertyWriter,
            Any(), "user", "user")).isFalse()
    }

    private fun getAnnotation(name: String) = ReflectionUtils.findField(
        TestBasicRoleBasedFieldSecurityPolicy::class.java, name)
            .getAnnotation(SecureField::class.java)
}