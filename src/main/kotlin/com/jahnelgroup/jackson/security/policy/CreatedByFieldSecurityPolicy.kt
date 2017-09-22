package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import org.springframework.context.ApplicationContext

/**
 * Policy that permits access only to the creator of the target POJO. This
 * is the default policy.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
class CreatedByFieldSecurityPolicy : FieldSecurityPolicy {

    override fun permitAccess(writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean =
            targetCreatedByUser == currentPrincipalUser

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        // nothing
    }

}