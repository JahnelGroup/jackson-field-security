package com.jahnelgroup.jackson.security.principal

/**
 * Defines the specification for determining the current logged in
 * principal.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
interface PrincipalProvider {

    /**
     * @return the current logged in principal username
     */
    fun getCurrentPrincipal() : String

}