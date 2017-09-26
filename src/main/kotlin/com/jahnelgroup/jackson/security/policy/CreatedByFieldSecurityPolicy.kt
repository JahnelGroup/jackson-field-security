package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.jahnelgroup.jackson.security.SecureField

/**
 * Policy that permits access only to the creator of the target POJO. This
 * is the default policy.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
class CreatedByFieldSecurityPolicy : FieldSecurityPolicy {

    override fun permitAccess(secureField: SecureField, writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean =
        targetCreatedByUser == currentPrincipalUser

}