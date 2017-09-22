package com.jahnelgroup.jackson.security.principal

import org.springframework.security.core.context.SecurityContextHolder

class SpringSecurityPrincipalAware : PrincipalAware {

    override fun getCurrentPrincipal() =
        SecurityContextHolder.getContext().authentication.name

}