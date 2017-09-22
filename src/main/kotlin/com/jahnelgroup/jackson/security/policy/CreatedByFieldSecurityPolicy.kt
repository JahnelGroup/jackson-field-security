package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import org.springframework.context.ApplicationContext

/**
 * CreatedByFieldSecurityPolicy
 */
class CreatedByFieldSecurityPolicy : FieldSecurityPolicy {

    override fun permitAccess(writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean =
            targetCreatedByUser == currentPrincipalUser

    override fun setApplicationContext(applicationContext: ApplicationContext) {
        // not required
        applicationContext.getBean("userRepository")

        var one : List<Long> = ArrayList()
        var two : List<Long> = ArrayList()

        one.stream().anyMatch(two::contains)
    }

}