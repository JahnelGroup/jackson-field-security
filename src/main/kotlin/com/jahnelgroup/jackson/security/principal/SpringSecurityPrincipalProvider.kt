package com.jahnelgroup.jackson.security.principal

import org.springframework.security.core.context.SecurityContextHolder

/**
 * Provider that will use Spring Security's [SecurityContextHolder] to
 * identify the current logged in principal name.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
class SpringSecurityPrincipalProvider : PrincipalProvider {

    override fun getCurrentPrincipal() =
        SecurityContextHolder.getContext().authentication.name

    override fun getRoles(): List<String> =
        SecurityContextHolder.getContext().authentication.authorities.map {
            it.toString()
        }

}