package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter

interface FieldSecurityPolicy {

    fun permitAccess(writer: PropertyWriter, target : Any, targetCreatedByUser : String?, currentPrincipalUser : String?) : Boolean

}