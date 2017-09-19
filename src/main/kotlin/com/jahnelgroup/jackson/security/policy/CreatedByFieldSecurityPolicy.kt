package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter

class CreatedByFieldSecurityPolicy : FieldSecurityPolicy {

    override fun permitAccess(writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean =
            targetCreatedByUser == currentPrincipalUser

}