package com.jahnelgroup.jackson.security.exception

/**
 * Defines the specification for determining if an exception should
 * be considered access denied or propagated up further.
 *
 * @author Steven Zgaljic
 * @since 1.0.3
 */
interface AccessDeniedExceptionHandler {

    /**
     * Determines if an exception should be considered as access denied.
     *
     * @param[exception] exception thrown when analyzing a field
     */
    @Throws(Exception::class)
    fun permitAccess(exception : Exception) : Boolean

}