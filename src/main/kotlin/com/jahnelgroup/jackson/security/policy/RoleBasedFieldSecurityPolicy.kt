package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.slf4j.LoggerFactory

class RoleBasedFieldSecurityPolicy(
    var principalProvider: PrincipalProvider
) : FieldSecurityPolicy {

    companion object {
        private val log = LoggerFactory.getLogger(RoleBasedFieldSecurityPolicy::class.java)
    }

    override fun permitAccess(secureField: SecureField, writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean {
        var permit : Boolean? = null

        val formattedRoles : List<String> = secureField.roles.map {
            if (it.startsWith("ROLE_")) it else "ROLE_" + it
        }

        roles@ for(it in formattedRoles){
            var passed = principalProvider.getRoles()?.contains(it) ?: false
            log.debug("Role ${if (passed) "Passed" else "Failed"}: $it")

            when( secureField.roleLogic ) {
                EvalulationLogic.AND -> {
                    permit = permit?.and(passed) ?: passed
                    if(!permit) break@roles
                }

                EvalulationLogic.OR -> {
                    permit = permit?.or(passed) ?: passed
                    if(permit) break@roles
                }

                EvalulationLogic.XOR -> {
                    permit = permit?.xor(passed) ?: passed
                }
            }
        }

        return permit ?: false
    }

}