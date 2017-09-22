package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import org.springframework.context.ApplicationContextAware

/**
 * FieldSecurityPolicy
 */
interface FieldSecurityPolicy : ApplicationContextAware {

    fun permitAccess(writer: PropertyWriter, target : Any, targetCreatedByUser : String?, currentPrincipalUser : String?) : Boolean

}