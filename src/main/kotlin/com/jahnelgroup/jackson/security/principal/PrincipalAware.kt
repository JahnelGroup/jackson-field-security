package com.jahnelgroup.jackson.security.principal

/**
 * PrincipalAware
 */
interface PrincipalAware {

    fun getCurrentPrincipal() : String

}