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

        val formattedRoles : List<String> = secureField.roles.map {
            if (it.startsWith("ROLE_")) it else "ROLE_" + it
        }

        return when( secureField.roleLogic ) {
            EvalulationLogic.AND -> {
                formattedRoles.takeWhile {
                    permitRole(it)
                }.size == formattedRoles.size
            }

            EvalulationLogic.OR -> {
                formattedRoles.firstOrNull{
                    permitRole(it)
                }.orEmpty().isNotEmpty()
            }

            EvalulationLogic.XOR -> {
                formattedRoles.filter {
                    permitRole(it)
                }.size == 1
            }
        }
    }

    fun permitRole(role: String) : Boolean {
        var permit = principalProvider.getRoles()?.contains(role) ?: false
        log.debug("Role ${if (permit) "Passed" else "Failed"}: $role")
        return permit
    }

}