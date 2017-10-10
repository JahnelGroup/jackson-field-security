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

    override fun permitAccess(secureField: SecureField, writer: PropertyWriter, target: Any,
                              targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean {
        var permit : Boolean? = null

        val formattedRoles : List<String> = secureField.roles.map {
            if (it.startsWith("ROLE_")) it else "ROLE_" + it
        }

        val passedRoles = mutableListOf<String>()

        roles@ for(it in formattedRoles){
            var passed = principalProvider.getRoles()?.contains(it) ?: false
            if(passed) passedRoles.add(it)
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
            }
        }

        if( secureField.roleLogic == EvalulationLogic.XOR ){
            permit = passedRoles.size == 1
        }

        return permit ?: false
    }

}