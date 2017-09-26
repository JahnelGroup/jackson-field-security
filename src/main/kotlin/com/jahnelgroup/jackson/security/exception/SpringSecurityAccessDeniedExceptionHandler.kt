package com.jahnelgroup.jackson.security.exception

/**
 * Autoconfiguration for [AccessDeniedExceptionHandler].
 *
 * @author Steven Zgaljic
 * @since 1.0.3
 */
class SpringSecurityAccessDeniedExceptionHandler : AccessDeniedExceptionHandler{
    override fun permitAccess(exception: Exception): Boolean {
        if( exception !is org.springframework.security.access.AccessDeniedException ){
            throw exception
        }
        return false
    }

}